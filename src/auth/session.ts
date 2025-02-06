import type { PrismaClient } from "@prisma/client";
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
  const { logger, sessionMaxAgeSec } = config;
  try {
    const { prefix, suffix } = generateTokenParts();
    const suffixHash = await hashSuffix(suffix);

    const expiresAt = new Date(Date.now() + sessionMaxAgeSec * 1000);

    await prisma.session.create({
      data: {
        userId: options.userId,
        tokenPrefix: prefix,
        tokenHash: suffixHash,
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
  const { logger, sessionMaxAgeSec, sessionUpdateAgeSec } = config;
  try {
    const prefix = rawToken.slice(0, 16);
    const suffix = rawToken.slice(16);

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

    const match = await verifySuffixHash(session.tokenHash, suffix);
    if (!match) {
      return {
        error: true,
        status: 401,
        message: "Session invalid or expired.",
      };
    }

    // "Sliding" expiration logic
    const now = Date.now();
    const originalExpiresTime = session.expiresAt.getTime();
    const updateThreshold =
      originalExpiresTime -
      sessionMaxAgeSec * 1000 +
      sessionUpdateAgeSec * 1000;

    let updatedSession = session;

    if (now > updateThreshold) {
      // extend the session
      const newExpiresAt = new Date(now + sessionMaxAgeSec * 1000);
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
    const prefix = rawToken.slice(0, 16);
    const suffix = rawToken.slice(16);

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

    const match = await verifySuffixHash(session.tokenHash, suffix);
    if (!match) {
      return {
        error: true,
        status: 401,
        message: "Session invalid or expired.",
      };
    }

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
