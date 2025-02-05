import type { PrismaClient } from "@prisma/client";
import { APP_CONFIG } from "../config";
import {
  generateTokenParts,
  hashSuffix,
  verifySuffixHash,
} from "../crypto/session-token";
import type { AuthSession } from "../interfaces";
import type { SpectraAuthResult } from "../types";

export interface CreateSessionOptions {
  /** The user ID to link this session to. */
  userId: string;
  /** Optional device info (IP address, browser, etc.). */
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
 *
 * @param prisma  - The PrismaClient instance.
 * @param options - { userId, deviceInfo }
 * @returns       - A SpectraAuthResult with success or error details.
 */
export async function createSession(
  prisma: PrismaClient,
  options: CreateSessionOptions,
): Promise<SpectraAuthResult> {
  try {
    const { prefix, suffix } = generateTokenParts();
    const suffixHash = await hashSuffix(suffix);

    const expiresAt = new Date(Date.now() + APP_CONFIG.sessionMaxAgeSec * 1000);

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

    return {
      error: false,
      status: 200,
      message: "Session created successfully.",
      data: { rawToken: prefix + suffix },
    };
  } catch (err) {
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to create session",
    };
  }
}

/**
 * Validates a raw session token (prefix+suffix) and applies a "throttled" sliding expiration.
 *
 * @param prisma   - The PrismaClient instance.
 * @param rawToken - The raw session token from the client (e.g. cookie).
 * @returns        - A SpectraAuthResult with the updated session or an error.
 */
export async function validateSession(
  prisma: PrismaClient,
  rawToken: string,
): Promise<SpectraAuthResult> {
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

    // Throttled sliding expiration
    const now = Date.now();
    const sessionIsDueToBeUpdated =
      session.expiresAt.getTime() -
      APP_CONFIG.sessionMaxAgeSec * 1000 +
      APP_CONFIG.sessionUpdateAgeSec * 1000;

    let updatedSession = session;

    if (now > sessionIsDueToBeUpdated) {
      const newExpiresAt = new Date(now + APP_CONFIG.sessionMaxAgeSec * 1000);
      updatedSession = (await prisma.session.update({
        where: { id: session.id },
        data: { expiresAt: newExpiresAt },
        include: { user: true },
      })) as AuthSession;
    }

    return {
      error: false,
      status: 200,
      message: "Session validated successfully.",
      data: { session: updatedSession },
    };
  } catch (err) {
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to validate session",
    };
  }
}

/**
 * Revokes (invalidates) the session matching the given raw token.
 *
 * @param prisma   - The PrismaClient instance.
 * @param rawToken - The raw session token (prefix+suffix) to revoke.
 * @returns        - A SpectraAuthResult with success or error details.
 */
export async function revokeSession(
  prisma: PrismaClient,
  rawToken: string,
): Promise<SpectraAuthResult> {
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

    return {
      error: false,
      status: 200,
      message: "Session revoked successfully.",
    };
  } catch (err) {
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to revoke session",
    };
  }
}
