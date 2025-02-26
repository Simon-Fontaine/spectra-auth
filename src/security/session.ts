import type { Prisma, PrismaClient, Session } from "@prisma/client";
import { ErrorCode, SessionState } from "../constants";
import type {
  AegisAuthConfig,
  AegisResponse,
  AuthCookies,
  CreateSessionOptions,
  SessionMetadata,
  SessionToken,
  SessionValidationResult,
} from "../types";
import { createCsrfCookie, createSessionCookie } from "../utils/cookies";
import { createOperation } from "../utils/error";
import { generateFingerprint, validateFingerprint } from "../utils/fingerprint";
import { fail, success } from "../utils/response";
import { addTime, createTime, isExpired } from "../utils/time";
import { createHmac } from "./crypto";
import { generateCsrfToken, generateSessionToken } from "./tokens";

/**
 * Creates a new authenticated session
 *
 * @param prisma - Prisma client instance
 * @param config - Authentication configuration
 * @param options - Session creation options
 * @returns Response with session and cookies
 */
export const createSession = createOperation(
  "createSession",
  ErrorCode.SESSION_TOKEN_ERROR,
  "Failed to create session",
)(
  async (
    prisma: PrismaClient,
    config: AegisAuthConfig,
    options: CreateSessionOptions,
  ): Promise<AegisResponse<{ session: Session; cookies: AuthCookies }>> => {
    const {
      userId,
      ipAddress,
      userAgent,
      locationData,
      deviceData,
      metadata = {},
    } = options;

    // Generate session token
    const sessionTokenResult = await generateSessionToken(config);
    if (!sessionTokenResult.success) {
      return sessionTokenResult;
    }

    // Generate CSRF token
    const csrfTokenResult = await generateCsrfToken(config);
    if (!csrfTokenResult.success) {
      return csrfTokenResult;
    }

    // Extract tokens and hashes
    const { token: sessionToken, hash: sessionTokenHash } =
      sessionTokenResult.data;
    const { token: csrfToken, hash: csrfTokenHash } = csrfTokenResult.data;

    // Calculate expiration date
    const expiresAt =
      options.expiresAt ||
      addTime(new Date(), config.session.absoluteMaxLifetimeSeconds, "s");

    // Combine metadata
    const sessionMetadata: SessionMetadata = {
      ...metadata,
      device: deviceData,
      location: locationData,
      userAgent,
      lastActive: new Date().toISOString(),
    };

    // Generate browser fingerprint if enabled and headers are available
    if (config.session.fingerprintOptions?.enabled && options.userAgent) {
      // Mock Headers object for generateFingerprint
      const headers = new Headers();
      if (options.userAgent) {
        headers.set("user-agent", options.userAgent);
      }

      const fingerprintResult = await generateFingerprint({
        ip: ipAddress,
        userAgent: options.userAgent,
        headers,
        config,
      });

      if (fingerprintResult.success) {
        sessionMetadata.fingerprint = fingerprintResult.data;
      }
    }

    // Create session in database
    const session = await prisma.$transaction(async (tx) => {
      // Enforce maximum session limit if configured
      if (config.account.maxSimultaneousSessions > 0) {
        const activeSessions = await tx.session.findMany({
          where: {
            userId,
            isRevoked: false,
          },
          orderBy: {
            createdAt: "asc",
          },
        });

        const excessSessions = Math.max(
          0,
          activeSessions.length - config.account.maxSimultaneousSessions + 1,
        );

        if (excessSessions > 0) {
          const sessionsToRevoke = activeSessions.slice(0, excessSessions);

          if (sessionsToRevoke.length > 0) {
            await tx.session.updateMany({
              where: {
                id: {
                  in: sessionsToRevoke.map((s) => s.id),
                },
              },
              data: {
                isRevoked: true,
              },
            });

            config.logger?.info("Revoked older sessions due to limit", {
              userId,
              revokedCount: sessionsToRevoke.length,
            });
          }
        }
      }

      // Create the new session
      return tx.session.create({
        include: {
          user: {
            include: {
              userRoles: {
                include: {
                  role: true,
                },
              },
            },
          },
        },
        data: {
          userId,
          tokenHash: sessionTokenHash,
          csrfTokenHash,
          expiresAt,
          ipAddress,
          metadata: sessionMetadata as Prisma.InputJsonValue,
        },
      });
    });

    // Create cookies
    const sessionCookie = createSessionCookie(sessionToken as string, config);
    const csrfCookie = createCsrfCookie(csrfToken as string, config);

    return success({
      session,
      cookies: {
        sessionCookie,
        csrfCookie,
      },
    });
  },
);

/**
 * Validates and potentially rotates a session
 *
 * @param prisma - Prisma client instance
 * @param config - Authentication configuration
 * @param sessionToken - Current session token
 * @param headers - Request headers
 * @returns Response with validation result
 */
export const validateSession = createOperation(
  "validateSession",
  ErrorCode.SESSION_INVALID,
  "Failed to validate session",
)(
  async (
    prisma: PrismaClient,
    config: AegisAuthConfig,
    sessionToken: SessionToken,
    headers: Headers,
  ): Promise<AegisResponse<SessionValidationResult>> => {
    // Verify the token to get the hash
    const tokenHashResult = await createHmac(
      "SHA-256",
      config.session.secret,
      sessionToken as string,
      "base64url",
    );

    if (!tokenHashResult.success) {
      return tokenHashResult;
    }

    const tokenHash = tokenHashResult.data;

    // Find the session
    const session = await prisma.session.findUnique({
      where: {
        tokenHash,
      },
      include: {
        user: {
          include: {
            userRoles: {
              include: {
                role: true,
              },
            },
          },
        },
      },
    });

    // Check if session exists
    if (!session) {
      return fail(
        ErrorCode.SESSION_INVALID,
        "Invalid session token",
        undefined,
        { reason: "session_not_found" },
      );
    }

    // Check if session is revoked
    if (session.isRevoked) {
      return fail(
        ErrorCode.SESSION_REVOKED,
        "Session has been revoked",
        undefined,
        { reason: "session_revoked" },
      );
    }

    // Check if session is expired
    if (isExpired(session.expiresAt)) {
      // Automatically revoke expired sessions
      await prisma.session.update({
        where: {
          id: session.id,
        },
        data: {
          isRevoked: true,
        },
      });

      return fail(ErrorCode.SESSION_EXPIRED, "Session has expired", undefined, {
        reason: "session_expired",
      });
    }

    // Check user status
    if (session.user.isBanned) {
      return fail(ErrorCode.AUTH_USER_BANNED, "User is banned", undefined, {
        reason: "user_banned",
      });
    }

    // Check inactivity timeout
    if (config.session.idleTimeoutSeconds) {
      const lastActivity = session.updatedAt;
      const now = new Date();
      const idleTimeout = createTime(config.session.idleTimeoutSeconds, "s");

      if (
        now.getTime() - lastActivity.getTime() >
        idleTimeout.toMilliseconds()
      ) {
        await prisma.session.update({
          where: {
            id: session.id,
          },
          data: {
            isRevoked: true,
          },
        });

        return fail(
          ErrorCode.SESSION_EXPIRED,
          "Session expired due to inactivity",
          undefined,
          { reason: "idle_timeout" },
        );
      }
    }

    // Extract session metadata
    const metadata = (session.metadata as SessionMetadata) || {};

    // Verify fingerprint if enabled
    if (config.session.fingerprintOptions?.enabled) {
      const currentFingerprintResult = await generateFingerprint({
        ip: session.ipAddress || undefined,
        userAgent: headers.get("user-agent") || undefined,
        headers,
        config,
      });

      if (currentFingerprintResult.success) {
        const fingerprintResult = await validateFingerprint(
          currentFingerprintResult.data,
          metadata.fingerprint,
          config,
        );

        if (!fingerprintResult.success) {
          if (config.session.fingerprintOptions.strictValidation) {
            await prisma.session.update({
              where: {
                id: session.id,
              },
              data: {
                isRevoked: true,
              },
            });

            return fail(
              ErrorCode.SESSION_FINGERPRINT_MISMATCH,
              "Session fingerprint mismatch",
              undefined,
              { reason: "fingerprint_mismatch" },
            );
          }
          config.logger?.warn(
            "Session fingerprint mismatch (non-strict mode)",
            {
              sessionId: session.id,
              userId: session.userId,
            },
          );
        }
      }
    }

    // Check if session needs rotation
    const lastUpdated = session.updatedAt.getTime();
    const now = new Date().getTime();
    const refreshInterval = config.session.refreshIntervalSeconds * 1000;
    const rotationThreshold =
      refreshInterval * (config.session.rotationFraction || 0.5);

    const needsRotation = now - lastUpdated > rotationThreshold;

    // If rotation is needed, create new tokens and update session
    if (needsRotation) {
      // Generate new session token
      const sessionTokenResult = await generateSessionToken(config);
      if (!sessionTokenResult.success) {
        return sessionTokenResult;
      }

      // Generate new CSRF token
      const csrfTokenResult = await generateCsrfToken(config);
      if (!csrfTokenResult.success) {
        return csrfTokenResult;
      }

      // Extract new tokens and hashes
      const { token: newSessionToken, hash: newSessionTokenHash } =
        sessionTokenResult.data;
      const { token: newCsrfToken, hash: newCsrfTokenHash } =
        csrfTokenResult.data;

      // Update session with new tokens and extend expiration
      const updatedSession = await prisma.session.update({
        where: {
          id: session.id,
        },
        include: {
          user: {
            include: {
              userRoles: {
                include: {
                  role: true,
                },
              },
            },
          },
        },
        data: {
          tokenHash: newSessionTokenHash,
          csrfTokenHash: newCsrfTokenHash,
          expiresAt: addTime(
            new Date(),
            config.session.absoluteMaxLifetimeSeconds,
            "s",
          ),
          metadata: {
            ...metadata,
            lastActive: new Date().toISOString(),
          },
        },
      });

      // Create new cookies
      const sessionCookie = createSessionCookie(
        newSessionToken as string,
        config,
      );
      const csrfCookie = createCsrfCookie(newCsrfToken as string, config);

      return success({
        isValid: true,
        state: SessionState.ACTIVE,
        session: updatedSession,
        rotated: true,
        sessionToken: newSessionToken,
        csrfToken: newCsrfToken,
        sessionCookie,
        csrfCookie,
      });
    }

    // If no rotation needed, just update last activity time
    await prisma.session.update({
      where: {
        id: session.id,
      },
      data: {
        metadata: {
          ...metadata,
          lastActive: new Date().toISOString(),
        },
      },
    });

    return success({
      isValid: true,
      state: SessionState.ACTIVE,
      session,
      rotated: false,
    });
  },
);

/**
 * Revokes a session
 *
 * @param prisma - Prisma client instance
 * @param sessionId - ID of session to revoke
 * @returns Response with revocation result
 */
export const revokeSession = createOperation(
  "revokeSession",
  ErrorCode.SESSION_REVOKED,
  "Failed to revoke session",
)(
  async (
    prisma: PrismaClient,
    sessionId: string,
  ): Promise<AegisResponse<boolean>> => {
    const session = await prisma.session.update({
      where: {
        id: sessionId,
      },
      data: {
        isRevoked: true,
      },
    });

    return success(session.isRevoked);
  },
);

/**
 * Revokes all sessions for a user
 *
 * @param prisma - Prisma client instance
 * @param userId - User ID
 * @param exceptSessionId - Optional session ID to exclude from revocation
 * @returns Response with number of revoked sessions
 */
export const revokeAllUserSessions = createOperation(
  "revokeAllUserSessions",
  ErrorCode.SESSION_REVOKED,
  "Failed to revoke user sessions",
)(
  async (
    prisma: PrismaClient,
    userId: string,
    exceptSessionId?: string,
  ): Promise<AegisResponse<number>> => {
    const whereClause: Prisma.SessionWhereInput = {
      userId,
      isRevoked: false,
    };

    if (exceptSessionId) {
      whereClause.id = { not: exceptSessionId };
    }

    const result = await prisma.session.updateMany({
      where: whereClause,
      data: {
        isRevoked: true,
      },
    });

    return success(result.count);
  },
);
