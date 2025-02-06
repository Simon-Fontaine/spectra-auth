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

/** Options for creating a session */
export interface CreateSessionOptions {
  /** The user ID for which the session is being created. */
  userId: string;
  /** Device metadata (location, browser, etc.) */
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
 *
 * - Generates a secure session token.
 * - Enforces session concurrency limits.
 * - Stores session details in the database.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - The configuration for session management.
 * @param options - The options containing the user ID and device information.
 * @returns A result containing the session token if successful.
 */
export async function createSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: CreateSessionOptions,
): Promise<SpectraAuthResult> {
  const { logger, session } = config;
  try {
    // Step 1: Enforce session concurrency limit if configured
    if (session.maxSessionsPerUser > 0) {
      const activeCount = await prisma.session.count({
        where: {
          userId: options.userId,
          isRevoked: false,
          expiresAt: { gt: new Date() },
        },
      });

      if (activeCount >= session.maxSessionsPerUser) {
        const oldest = await prisma.session.findFirst({
          where: {
            userId: options.userId,
            isRevoked: false,
            expiresAt: { gt: new Date() },
          },
          orderBy: { createdAt: "asc" },
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

    // Step 2: Generate session token parts
    const { prefix, suffix } = generateTokenParts();
    const suffixHash = await hashSuffix(suffix);

    // Step 3: Generate a random per-session CSRF secret
    const csrfSecretArr = new Uint8Array(32);
    getRandomValues(csrfSecretArr);
    const csrfSecretHex = hex.encode(csrfSecretArr);

    const expiresAt = new Date(Date.now() + session.maxAgeSec * 1000);

    // Step 4: Create session entry in the database
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
 * Validates a raw session token and renews it if necessary.
 *
 * - Checks if the session token is valid and not expired.
 * - Renews the session if it is near expiration.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - The configuration for session management.
 * @param rawToken - The session token to validate.
 * @returns A result containing the session details if successful.
 */
export async function validateSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  const { logger } = config;
  try {
    // Step 1: Extract token parts
    const prefix = rawToken.slice(0, 16);
    const suffix = rawToken.slice(16);

    // Step 2: Find the session entry in the database
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

    // Step 3: Verify token suffix hash
    const match = await verifySuffixHash(session.tokenHash, suffix);
    if (!match) {
      return {
        error: true,
        status: 401,
        message: "Session invalid or expired.",
      };
    }

    // Step 4: Check if session renewal is necessary
    const now = Date.now();
    const originalExpiresTime = session.expiresAt.getTime();
    const updateThreshold =
      originalExpiresTime -
      config.session.maxAgeSec * 1000 +
      config.session.updateAgeSec * 1000;

    let updatedSession = session;

    if (now > updateThreshold) {
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
 * Revokes an active session identified by its raw token.
 *
 * - Checks if the session token exists and is active.
 * - Revokes the session to prevent further use.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - The configuration for session management.
 * @param rawToken - The session token to revoke.
 * @returns A result indicating whether the session was successfully revoked.
 */
export async function revokeSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  const { logger } = config;
  try {
    // Step 1: Extract token parts
    const prefix = rawToken.slice(0, 16);
    const suffix = rawToken.slice(16);

    // Step 2: Find the session
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

    // Step 3: Verify the token suffix
    const match = await verifySuffixHash(session.tokenHash, suffix);
    if (!match) {
      return {
        error: true,
        status: 401,
        message: "Session invalid or expired.",
      };
    }

    // Step 4: Revoke the session
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
