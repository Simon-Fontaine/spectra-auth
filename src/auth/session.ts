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
import type { AuthSession } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";

/**
 * Creates a new user session.
 *
 * - Generates a unique session token and prefix.
 * - Hashes the session token for secure storage.
 * - Stores session data in the database, including device info and expiry.
 *
 * @param prisma - Prisma client instance.
 * @param config - Authentication configuration.
 * @param options - Options including userId and deviceInfo.
 * @returns Result containing the raw session token and user ID on success.
 */
export async function createSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: CreateSessionOptions,
): Promise<SpectraAuthResult> {
  try {
    const { userId, deviceInfo } = options;
    const sessionToken = await generateSessionToken(
      config.session.tokenLengthBytes,
    ); // Generate full session token
    const tokenPrefix = await generateTokenPrefix(
      config.session.tokenPrefixLengthBytes,
    ); // Shorter prefix for indexing
    const tokenHash = await createHMAC("SHA-256", "base64urlnopad").sign(
      sessionToken,
      config.session.tokenSecret,
    ); // HMAC hash of the token

    const sessionExpiresAt = new Date(
      Date.now() + config.session.maxAgeSec * 1000,
    ); // Session expiration date

    // Create session record in database
    const session = (await prisma.session.create({
      data: {
        userId: userId,
        tokenPrefix: tokenPrefix,
        tokenHash: tokenHash,
        expiresAt: sessionExpiresAt,
        ipAddress: deviceInfo?.ipAddress,
        location: deviceInfo?.location,
        country: deviceInfo?.country,
        device: deviceInfo?.device,
        browser: deviceInfo?.browser,
        userAgent: deviceInfo?.userAgent,
      },
    })) as AuthSession; // Type assertion for known structure

    config.logger.info("Session created", {
      sessionId: session.id,
      userId: userId,
      tokenPrefix: tokenPrefix,
      expiresAt: session.expiresAt,
    });

    return {
      error: false,
      status: 201, // Created
      message: "Session created successfully",
      data: {
        sessionId: session.id,
        userId: userId,
        rawToken: sessionToken, // Return the raw, unhashed token to be set as cookie
      },
    };
  } catch (error) {
    config.logger.error("Error creating session", { error: error });
    return {
      error: true,
      status: 500,
      message: "Failed to create session",
    };
  }
}

/**
 * Validates a session token.
 *
 * - Extracts the token prefix from the raw token.
 * - Looks up the session in the database by token prefix.
 * - Verifies the token hash against the stored hash.
 * - Checks if the session is expired or revoked.
 *
 * @param prisma - Prisma client instance.
 * @param config - Authentication configuration.
 * @param rawToken - The raw session token from the client.
 * @returns Result containing session data if valid, or an error.
 */
export async function validateSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  try {
    if (!rawToken) {
      throw new AuthenticationError(
        "No session token provided",
        401,
        "E_TOKEN_REQUIRED",
      );
    }

    const tokenPrefix = rawToken.slice(
      0,
      config.session.tokenPrefixLengthBytes * 2,
    ); // Extract prefix (hex encoded, so *2)

    if (tokenPrefix.length !== config.session.tokenPrefixLengthBytes * 2) {
      throw new AuthenticationError(
        "Invalid session token format (prefix length)",
        400,
        "E_TOKEN_INVALID_FORMAT",
      );
    }

    // Step 1: Retrieve session by token prefix (indexed)
    const session = (await prisma.session.findFirst({
      where: { tokenPrefix: tokenPrefix },
    })) as AuthSession | null;

    if (!session) {
      config.logger.warn("Session not found (prefix lookup)", {
        tokenPrefix: tokenPrefix,
      });
      throw new SessionNotFoundError(
        "Session not found",
        404,
        "E_SESSION_NOT_FOUND",
      );
    }

    // Step 2: Verify token hash against stored hash
    const isTokenValid = await createHMAC().verify(
      config.session.tokenSecret,
      session.tokenHash || "",
      rawToken,
    );
    if (!isTokenValid) {
      config.logger.warn("Session token hash mismatch", {
        sessionId: session.id,
        tokenPrefix: tokenPrefix,
      });
      await revokeSessionInternal(prisma, session.id, config); // Revoke session on hash mismatch for security
      throw new AuthenticationError(
        "Invalid session token (hash mismatch)",
        401,
        "E_TOKEN_INVALID_HASH",
      ); // More generic error for client
    }

    // Step 3: Check if session is revoked
    if (session.isRevoked) {
      config.logger.warn("Session is revoked", {
        sessionId: session.id,
        tokenPrefix: tokenPrefix,
      });
      throw new SessionRevokedError(
        "Session is revoked",
        401,
        "E_SESSION_REVOKED",
      );
    }

    // Step 4: Check if session is expired
    if (session.expiresAt < new Date()) {
      config.logger.warn("Session expired", {
        sessionId: session.id,
        tokenPrefix: tokenPrefix,
        expiresAt: session.expiresAt,
      });
      await revokeSessionInternal(prisma, session.id, config); // Revoke expired session
      throw new SessionRevokedError(
        "Session expired",
        401,
        "E_SESSION_EXPIRED",
      ); // SessionRevokedError to indicate logout is needed
    }

    config.logger.info("Session validated", {
      sessionId: session.id,
      userId: session.userId,
      tokenPrefix: tokenPrefix,
      expiresAt: session.expiresAt,
    });

    return {
      error: false,
      status: 200,
      message: "Session is valid",
      data: { session: session }, // Return session data (consider what data to expose)
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
    config.logger.error("Error validating session", { error: error });
    return {
      error: true,
      status: 500,
      message: "Session validation failed",
    };
  }
}

/**
 * Revokes a session token, rendering it invalid.
 *
 * - Calls the internal revocation function to update session status in DB.
 * - Logs the revocation event.
 *
 * @param prisma - Prisma client.
 * @param config - Auth config.
 * @param rawToken - The raw session token to revoke.
 * @returns Success result or error.
 */
export async function revokeSession(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  try {
    const tokenPrefix = rawToken.slice(
      0,
      config.session.tokenPrefixLengthBytes * 2,
    );

    const session = (await prisma.session.findFirst({
      where: { tokenPrefix: tokenPrefix },
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

    const result = await revokeSessionInternal(prisma, session.id, config); // Call internal revoke function

    if (!result.error) {
      config.logger.info("Session revoked", {
        sessionId: session.id,
        tokenPrefix: tokenPrefix,
      });
    } else {
      config.logger.warn("Session revocation failed", {
        sessionId: session.id,
        tokenPrefix: tokenPrefix,
        reason: result.message,
      });
    }

    return result;
  } catch (error) {
    config.logger.error("Error revoking session", { error: error });
    return {
      error: true,
      status: 500,
      message: "Failed to revoke session",
    };
  }
}

/**
 * Internal function to revoke a session by session ID.
 *  - Updates the session in the database to set 'isRevoked' to true.
 *  - Does NOT perform token validation - assumes session ID is valid and known.
 *  - Used by both `revokeSession` (after token prefix lookup) and `validateSession` (on token mismatch/expiry).
 *
 * @param prisma - Prisma client.
 * @param sessionId - The session ID (UUID) to revoke.
 * @param config - Auth config.
 * @returns Success or failure result.
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

    config.logger.debug("Session revoked in DB", { sessionId: sessionId }); // Debug level - internal operation

    return {
      error: false,
      status: 200,
      message: "Session revoked",
    };
  } catch (error) {
    config.logger.error("Error updating session to revoked", {
      sessionId: sessionId,
      error: error,
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
