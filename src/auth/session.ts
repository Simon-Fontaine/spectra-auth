import type { PrismaClient } from "@prisma/client";
import { createHMAC } from "../crypto/hmac";
import {
  generateSessionToken,
  generateTokenPrefix,
} from "../crypto/session-token";
import {
  AuthenticationError,
  SessionNotFoundError,
  SessionRevokedError,
} from "../errors";
import type { AuthSession, CleanAuthSession } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";

/**
 * Creates a new user session.
 *
 * - Generates a unique session token and prefix.
 * - Hashes the session token for secure storage.
 * - Stores session data in the database, including device info and expiry.
 * - Returns a "cleaned" session object (no tokenHash, prefix, etc.) plus the raw token.
 */
export async function createSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: CreateSessionOptions,
): Promise<SpectraAuthResult> {
  try {
    const { userId, deviceInfo } = options;

    // 1. Generate a random session token & prefix
    const sessionToken = await generateSessionToken(
      config.session.tokenLengthBytes,
    );
    const tokenPrefix = await generateTokenPrefix(
      config.session.tokenPrefixLengthBytes,
    );

    // 2. Create a hashed version of the token for DB storage
    const tokenHash = await createHMAC("SHA-256", "base64urlnopad").sign(
      sessionToken,
      config.session.tokenSecret,
    );

    // 3. Calculate when it expires
    const sessionExpiresAt = new Date(
      Date.now() + config.session.maxAgeSec * 1000,
    );

    // 4. Insert into DB
    const session = (await prisma.session.create({
      data: {
        userId,
        tokenPrefix,
        tokenHash,
        expiresAt: sessionExpiresAt,
        ipAddress: deviceInfo?.ipAddress,
        location: deviceInfo?.location,
        country: deviceInfo?.country,
        device: deviceInfo?.device,
        browser: deviceInfo?.browser,
        userAgent: deviceInfo?.userAgent,
      },
    })) as AuthSession;

    config.logger.info("Session created", {
      sessionId: session.id,
      userId,
      tokenPrefix,
      expiresAt: session.expiresAt,
    });

    // 5. Omit sensitive fields from the returned session
    const {
      tokenPrefix: _prefix,
      tokenHash: _hash,
      csrfSecret: _csrf,
      ...cleanSession
    } = session;

    // 6. Return the "clean" session plus the raw token
    const responseData: CleanAuthSession = {
      ...cleanSession,
      rawToken: sessionToken, // Return the raw token so client can store it in a cookie
    };

    return {
      error: false,
      status: 201,
      message: "Session created successfully",
      data: {
        ...responseData,
      },
    };
  } catch (error) {
    config.logger.error("Error creating session", { error });
    return {
      error: true,
      status: 500,
      message: "Failed to create session",
    };
  }
}

/**
 * Validates a session token by:
 * - Parsing out the token prefix.
 * - Looking up the DB record by token prefix.
 * - Verifying the HMAC of the raw token.
 * - Checking 'isRevoked' & 'expiresAt'.
 * - Potentially rolling (rotating) the session if older than rollingIntervalSec.
 *
 * @param prisma - Prisma client instance.
 * @param config - Auth config (includes rollingIntervalSec, etc.)
 * @param rawToken - The raw session token from the client.
 * @returns A SpectraAuthResult with either an error or { session, rolled?, newToken?, newSessionId?, ... }
 */
export async function validateSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  try {
    // 1. Sanity check
    if (!rawToken) {
      throw new AuthenticationError(
        "No session token provided",
        401,
        "E_TOKEN_REQUIRED",
      );
    }

    const prefixLen = config.session.tokenPrefixLengthBytes * 2; // times 2 for hex
    const tokenPrefix = rawToken.slice(0, prefixLen);

    if (tokenPrefix.length !== prefixLen) {
      throw new AuthenticationError(
        "Invalid session token format (prefix length)",
        400,
        "E_TOKEN_INVALID_FORMAT",
      );
    }

    // 2. Lookup DB by prefix
    const session = (await prisma.session.findFirst({
      where: { tokenPrefix },
    })) as AuthSession | null;

    if (!session) {
      config.logger.warn("Session not found (prefix lookup)", { tokenPrefix });
      throw new SessionNotFoundError(
        "Session not found",
        404,
        "E_SESSION_NOT_FOUND",
      );
    }

    // 3. Check the HMAC
    const isTokenValid = await createHMAC().verify(
      config.session.tokenSecret,
      session.tokenHash || "",
      rawToken,
    );
    if (!isTokenValid) {
      config.logger.warn("Session token hash mismatch", {
        sessionId: session.id,
        tokenPrefix,
      });
      await revokeSessionInternal(prisma, session.id, config);
      throw new AuthenticationError(
        "Invalid session token (hash mismatch)",
        401,
        "E_TOKEN_INVALID_HASH",
      );
    }

    // 4. Check isRevoked
    if (session.isRevoked) {
      config.logger.warn("Session is revoked", {
        sessionId: session.id,
        tokenPrefix,
      });
      throw new SessionRevokedError(
        "Session is revoked",
        401,
        "E_SESSION_REVOKED",
      );
    }

    // 5. Check expiration
    if (session.expiresAt < new Date()) {
      config.logger.warn("Session expired", {
        sessionId: session.id,
        tokenPrefix,
        expiresAt: session.expiresAt,
      });
      await revokeSessionInternal(prisma, session.id, config);
      throw new SessionRevokedError(
        "Session expired",
        401,
        "E_SESSION_EXPIRED",
      );
    }

    // 6. Possibly roll (rotate) the session if it’s too old
    const rolled = await maybeRollSession(prisma, config, session);

    config.logger.info("Session validated", {
      sessionId: session.id,
      userId: session.userId,
      tokenPrefix,
      expiresAt: session.expiresAt,
      rolled: rolled?.rolled || false,
    });

    return {
      error: false,
      status: 200,
      message: "Session is valid",
      // Return the original session or (rolled) info
      // Up to you how you shape this result
      data: {
        session,
        ...(rolled || {}),
      },
    };
  } catch (error) {
    if (
      error instanceof AuthenticationError ||
      error instanceof SessionNotFoundError ||
      error instanceof SessionRevokedError
    ) {
      return {
        error: true,
        status: error.status,
        message: error.message,
        code: error.code,
      };
    }
    config.logger.error("Error validating session", { error });
    return {
      error: true,
      status: 500,
      message: "Session validation failed",
    };
  }
}

/**
 * If session is older than config.session.rollingIntervalSec, create a new one, revoke the old, and return info.
 * Otherwise returns null, meaning no rolling occurred.
 */
async function maybeRollSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  oldSession: AuthSession,
): Promise<null | {
  rolled: true;
  newToken: string;
  newSessionId: string;
  newExpiresAt: Date;
}> {
  const { rollingIntervalSec } = config.session;
  if (!rollingIntervalSec || rollingIntervalSec <= 0) {
    // Rolling is disabled
    return null;
  }

  const sessionAgeMs = Date.now() - oldSession.createdAt.getTime();
  if (sessionAgeMs < rollingIntervalSec * 1000) {
    // Not old enough to roll
    return null;
  }

  // 1. Create a new session for the same user
  const newSessionResult = await createSession(prisma, config, {
    userId: oldSession.userId,
    deviceInfo: {
      ipAddress: oldSession.ipAddress || undefined,
      location: oldSession.location || undefined,
      country: oldSession.country || undefined,
      device: oldSession.device || undefined,
      browser: oldSession.browser || undefined,
      userAgent: oldSession.userAgent || undefined,
    },
  });

  if (newSessionResult.error || !newSessionResult.data) {
    config.logger.warn("Failed to roll session - new session creation failed");
    return null; // fallback, keep old session
  }

  // 2. Revoke the old session
  await revokeSessionInternal(prisma, oldSession.id, config);

  // 3. Extract relevant data from the new session
  const newData = newSessionResult.data as unknown as CleanAuthSession;
  return {
    rolled: true,
    newToken: String(newData.rawToken || ""),
    newSessionId: String(newData.id || ""),
    newExpiresAt: newData.expiresAt,
  };
}

/**
 * Revoke a session by raw token.
 */
export async function revokeSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  try {
    const prefixLen = config.session.tokenPrefixLengthBytes * 2;
    const tokenPrefix = rawToken.slice(0, prefixLen);

    const session = (await prisma.session.findFirst({
      where: { tokenPrefix },
    })) as AuthSession | null;

    if (!session) {
      config.logger.warn(
        "Revoke session attempt for non-existent session (prefix lookup)",
        { tokenPrefix },
      );
      return {
        error: true,
        status: 404,
        message: "Session not found for revocation",
        code: "E_SESSION_NOT_FOUND",
      };
    }

    const result = await revokeSessionInternal(prisma, session.id, config);
    if (!result.error) {
      config.logger.info("Session revoked", {
        sessionId: session.id,
        tokenPrefix,
      });
    } else {
      config.logger.warn("Session revocation failed", {
        sessionId: session.id,
        tokenPrefix,
        reason: result.message,
      });
    }

    return result;
  } catch (error) {
    config.logger.error("Error revoking session", { error });
    return {
      error: true,
      status: 500,
      message: "Failed to revoke session",
    };
  }
}

/**
 * Internal function that directly updates 'isRevoked' in the DB.
 * Used by both revokeSession and validateSession (for hash mismatch, etc.).
 */
async function revokeSessionInternal(
  prisma: PrismaClient,
  sessionId: string,
  config: Required<SpectraAuthConfig>,
): Promise<SpectraAuthResult> {
  try {
    await prisma.session.update({
      where: { id: sessionId },
      data: { isRevoked: true },
    });

    config.logger.debug("Session revoked in DB", { sessionId });

    return {
      error: false,
      status: 200,
      message: "Session revoked",
    };
  } catch (error) {
    config.logger.error("Error updating session to revoked", {
      sessionId,
      error,
    });
    return {
      error: true,
      status: 500,
      message: "Failed to revoke session in database",
    };
  }
}

/** Options for createSession function */
export interface CreateSessionOptions {
  /** User ID for whom to create the session. */
  userId: string;
  /** Device/location info (optional, for security/audit). */
  deviceInfo?: {
    ipAddress?: string;
    location?: string;
    country?: string;
    device?: string;
    browser?: string;
    userAgent?: string;
  };
}
