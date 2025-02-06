import type { PrismaClient } from "@prisma/client";
import { getRandomValues } from "uncrypto";
import { hex } from "../crypto/hex";
import {
  generateTokenParts,
  hashSuffix,
  verifySuffixHash,
} from "../crypto/session-token";
import type { AuthSession } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";

export interface CreateSessionOptions {
  userId: string;
  deviceInfo?: {
    ipAddress?: string;
    location?: string;
    country?: string;
    device?: string;
    browser?: string;
    userAgent?: string;
  };
}

/**
 * Creates a new session for the specified user ID.
 * Returns the raw token (prefix+suffix) in `data.rawToken`.
 */
export async function createSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: CreateSessionOptions,
): Promise<SpectraAuthResult> {
  const { logger, session } = config;
  try {
    // 1. (Optional) Enforce concurrency limit
    if (session.maxSessionsPerUser > 0) {
      const activeCount = await prisma.session.count({
        where: {
          userId: options.userId,
          isRevoked: false,
          expiresAt: { gt: new Date() },
        },
      });

      if (activeCount >= session.maxSessionsPerUser) {
        // Revoke the oldest session
        const oldest = await prisma.session.findFirst({
          where: {
            userId: options.userId,
            isRevoked: false,
            expiresAt: { gt: new Date() },
          },
          orderBy: { createdAt: "asc" }, // oldest first
        });
        if (oldest) {
          await prisma.session.update({
            where: { id: oldest.id },
            data: { isRevoked: true },
          });
          logger.warn("Revoked oldest session to enforce concurrency limit", {
            userId: options.userId,
            oldestSessionId: oldest.id,
          });
        }
      }
    }

    // 2. Generate session token
    const { prefix, suffix } = generateTokenParts();
    const suffixHash = await hashSuffix(suffix);

    // 3. Also generate a random per-session csrfSecret
    const csrfSecretArr = new Uint8Array(32);
    getRandomValues(csrfSecretArr);
    const csrfSecretHex = hex.encode(csrfSecretArr);

    const expiresAt = new Date(Date.now() + session.maxAgeSec * 1000);

    // 2. Create session
    await prisma.session.create({
      data: {
        userId: options.userId,
        tokenPrefix: prefix,
        tokenHash: suffixHash,
        csrfSecret: csrfSecretHex,
        expiresAt,
        ipAddress: options.deviceInfo?.ipAddress,
        location: options.deviceInfo?.location,
        country: options.deviceInfo?.country,
        device: options.deviceInfo?.device,
        browser: options.deviceInfo?.browser,
        userAgent: options.deviceInfo?.userAgent,
      },
    });

    logger.info("Session created", { userId: options.userId });

    return {
      error: false,
      status: 200,
      message: "Session created successfully.",
      data: { rawToken: prefix + suffix },
    };
  } catch (err) {
    logger.error("Failed to create session", { error: err });
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to create session",
    };
  }
}

/**
 * Validates a raw session token (prefix+suffix). If it's near expiration,
 * apply a "sliding" renewal if sessionUpdateAgeSec has elapsed.
 */
export async function validateSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  const { logger } = config;
  try {
    // 1. Extract token parts
    const prefix = rawToken.slice(0, 16);
    const suffix = rawToken.slice(16);

    // 2. Find session
    const session = (await prisma.session.findFirst({
      where: {
        tokenPrefix: prefix,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
      include: { user: true },
    })) as AuthSession | null;

    if (!session || !session.tokenHash) {
      return {
        error: true,
        status: 401,
        message: "Session invalid or expired.",
      };
    }

    // 3. Verify suffix hash
    const match = await verifySuffixHash(session.tokenHash, suffix);
    if (!match) {
      return {
        error: true,
        status: 401,
        message: "Session invalid or expired.",
      };
    }

    // 4. Check if session needs renewal (sliding expiration)
    const now = Date.now();
    const originalExpiresTime = session.expiresAt.getTime();
    const updateThreshold =
      originalExpiresTime -
      config.session.maxAgeSec * 1000 +
      config.session.updateAgeSec * 1000;

    let updatedSession = session;

    if (now > updateThreshold) {
      // extend the session
      const newExpiresAt = new Date(now + config.session.maxAgeSec * 1000);
      updatedSession = (await prisma.session.update({
        where: { id: session.id },
        data: { expiresAt: newExpiresAt },
        include: { user: true },
      })) as AuthSession;
      logger.info("Session extended", { sessionId: session.id });
    }

    return {
      error: false,
      status: 200,
      message: "Session validated successfully.",
      data: { session: updatedSession },
    };
  } catch (err) {
    logger.error("Failed to validate session", { error: err });
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to validate session",
    };
  }
}

/**
 * Revokes (invalidates) the session matching the given raw token.
 */
export async function revokeSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  const { logger } = config;
  try {
    // 1. Extract token parts
    const prefix = rawToken.slice(0, 16);
    const suffix = rawToken.slice(16);

    // 2. Find and revoke session
    const session = (await prisma.session.findFirst({
      where: {
        tokenPrefix: prefix,
        isRevoked: false,
        expiresAt: { gt: new Date() },
      },
    })) as AuthSession | null;
    if (!session || !session.tokenHash) {
      return { error: true, status: 404, message: "Session not found." };
    }

    // 3. Verify suffix hash
    const match = await verifySuffixHash(session.tokenHash, suffix);
    if (!match) {
      return {
        error: true,
        status: 401,
        message: "Session invalid or expired.",
      };
    }

    // 4. Revoke session
    await prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true },
    });
    logger.info("Session revoked", { sessionId: session.id });

    return {
      error: false,
      status: 200,
      message: "Session revoked successfully.",
    };
  } catch (err) {
    logger.error("Failed to revoke session", { error: err });
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to revoke session",
    };
  }
}
