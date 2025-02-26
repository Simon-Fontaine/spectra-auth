import type { Prisma, PrismaClient } from "@prisma/client";
import { ErrorCode, SessionState } from "../constants";
import { createCsrfCookie, createSessionCookie } from "../http/cookies";
import type {
  AegisAuthConfig,
  AegisResponse,
  AuthCookies,
  CreateSessionOptions,
  SessionMetadata,
  SessionToken,
  SessionValidationResult,
  SessionWithRelations,
} from "../types";
import { createOperation } from "../utils/error";
import { generateFingerprint, validateFingerprint } from "../utils/fingerprint";
import { fail, success } from "../utils/response";
import { addTime, createTime, isExpired } from "../utils/time";
import { createHmac } from "./crypto";
import { generateCsrfToken, generateSessionToken } from "./tokens";

/**
 * Revokes a session with a reason
 */
async function revokeSessionWithReason(
  prisma: PrismaClient | Prisma.TransactionClient,
  sessionId: string,
  reason: string,
  ipAddress?: string,
  metadata?: Record<string, unknown>,
): Promise<void> {
  const session = await prisma.session.findUnique({
    where: { id: sessionId },
    select: { metadata: true },
  });

  await prisma.session.update({
    where: { id: sessionId },
    data: {
      isRevoked: true,
      metadata: {
        ...((session?.metadata as Record<string, unknown>) || {}),
        revocationReason: reason,
        revokedAt: new Date().toISOString(),
        ipAddress,
        ...metadata,
      },
    },
  });
}

/**
 * Creates a new session
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
  ): Promise<
    AegisResponse<{ session: SessionWithRelations; cookies: AuthCookies }>
  > => {
    const {
      userId,
      ipAddress,
      userAgent,
      locationData,
      deviceData,
      metadata = {},
      expiresAt,
    } = options;

    const sessionTokenResult = await generateSessionToken(config);
    if (!sessionTokenResult.success) return sessionTokenResult;

    const csrfTokenResult = await generateCsrfToken(config);
    if (!csrfTokenResult.success) return csrfTokenResult;

    const { token: sessionToken, hash: sessionTokenHash } =
      sessionTokenResult.data;
    const { token: csrfToken, hash: csrfTokenHash } = csrfTokenResult.data;

    const finalExpiresAt =
      expiresAt ||
      addTime(new Date(), config.session.absoluteMaxLifetimeSeconds, "s");

    const sessionMetadata: SessionMetadata = {
      ...metadata,
      device: deviceData,
      location: locationData,
      userAgent,
      lastActive: new Date().toISOString(),
      createdAt: new Date().toISOString(),
      createdIp: ipAddress,
    };

    if (config.session.fingerprintOptions?.enabled && userAgent) {
      const headers = new Headers();
      headers.set("user-agent", userAgent);
      const fpResult = await generateFingerprint({
        ip: ipAddress,
        userAgent,
        headers,
        config,
      });
      if (fpResult.success) {
        sessionMetadata.fingerprint = fpResult.data;
      }
    }

    const session = await prisma.$transaction(async (tx) => {
      if (config.account.preventConcurrentSessions) {
        const existing = await tx.session.findMany({
          where: { userId, isRevoked: false },
        });
        if (existing.length > 0) {
          for (const s of existing) {
            await revokeSessionWithReason(
              tx,
              s.id,
              "preventConcurrentSessions",
              ipAddress,
            );
          }
        }
      } else if (config.account.maxSimultaneousSessions > 0) {
        const active = await tx.session.findMany({
          where: { userId, isRevoked: false },
          orderBy: { createdAt: "asc" },
        });
        const excess = Math.max(
          0,
          active.length - config.account.maxSimultaneousSessions + 1,
        );
        if (excess > 0) {
          const toRevoke = active.slice(0, excess);
          for (const s of toRevoke) {
            await revokeSessionWithReason(
              tx,
              s.id,
              "session_limit_exceeded",
              ipAddress,
              { newSessionCreated: true },
            );
          }
          config.logger?.info("Revoked older sessions due to limit", {
            userId,
            revokedCount: toRevoke.length,
          });
        }
      }

      return tx.session.create({
        include: {
          user: {
            include: {
              userRoles: { include: { role: true } },
            },
          },
        },
        data: {
          userId,
          tokenHash: sessionTokenHash,
          csrfTokenHash,
          expiresAt: finalExpiresAt,
          ipAddress,
          metadata: sessionMetadata as Prisma.InputJsonValue,
        },
      });
    });

    const sessionCookie = createSessionCookie(sessionToken, config);
    const csrfCookie = createCsrfCookie(csrfToken, config);

    return success({ session, cookies: { sessionCookie, csrfCookie } });
  },
);

/**
 * Validates and possibly rotates a session
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
    const hmac = await createHmac(
      "SHA-256",
      config.session.secret,
      sessionToken as string,
      "base64url",
    );
    if (!hmac.success) return hmac;

    const session = await prisma.session.findUnique({
      where: { tokenHash: hmac.data },
      include: {
        user: {
          include: {
            userRoles: { include: { role: true } },
          },
        },
      },
    });

    const ipAddress =
      headers.get("x-forwarded-for")?.split(",")[0].trim() ||
      headers.get("x-real-ip") ||
      "unknown";

    if (!session) {
      return fail(ErrorCode.SESSION_INVALID, "Invalid session token", {
        reason: "session_not_found",
      });
    }
    if (session.isRevoked) {
      return fail(ErrorCode.SESSION_REVOKED, "Session has been revoked", {
        reason: "session_revoked",
      });
    }
    if (isExpired(session.expiresAt)) {
      await revokeSessionWithReason(prisma, session.id, "expired", ipAddress, {
        expiryDate: session.expiresAt.toISOString(),
      });
      return fail(ErrorCode.SESSION_EXPIRED, "Session has expired", {
        reason: "session_expired",
      });
    }
    if (session.user.isBanned) {
      await revokeSessionWithReason(
        prisma,
        session.id,
        "user_banned",
        ipAddress,
      );
      return fail(ErrorCode.AUTH_USER_BANNED, "User is banned", {
        reason: "user_banned",
      });
    }
    if (config.session.idleTimeoutSeconds) {
      const now = new Date();
      const lastActivity = session.updatedAt;
      const idleLimit = createTime(config.session.idleTimeoutSeconds, "s");
      if (now.getTime() - lastActivity.getTime() > idleLimit.toMilliseconds()) {
        await revokeSessionWithReason(
          prisma,
          session.id,
          "idle_timeout",
          ipAddress,
          {
            lastActivity: lastActivity.toISOString(),
            idleTimeoutSeconds: config.session.idleTimeoutSeconds,
          },
        );
        return fail(
          ErrorCode.SESSION_EXPIRED,
          "Session expired due to inactivity",
          { reason: "idle_timeout" },
        );
      }
    }

    const metadata = (session.metadata as SessionMetadata) || {};
    if (config.session.fingerprintOptions?.enabled) {
      const userAgent = headers.get("user-agent") || undefined;
      const fpResult = await generateFingerprint({
        ip: session.ipAddress || undefined,
        userAgent,
        headers,
        config,
      });
      if (fpResult.success) {
        const check = await validateFingerprint(
          fpResult.data,
          metadata.fingerprint,
          config,
        );
        if (!check.success) {
          await revokeSessionWithReason(
            prisma,
            session.id,
            "fingerprint_mismatch",
            ipAddress,
            {
              currentFp: fpResult.data.substring(0, 8),
              storedFp: metadata.fingerprint
                ? metadata.fingerprint.substring(0, 8)
                : "missing",
            },
          );
          return fail(
            ErrorCode.SESSION_FINGERPRINT_MISMATCH,
            "Session fingerprint mismatch",
            { reason: "fingerprint_mismatch" },
          );
        }
      }
    }

    const now = Date.now();
    const lastUpdated = session.updatedAt.getTime();
    const refreshInterval = config.session.refreshIntervalSeconds * 1000;
    const rotateThreshold =
      refreshInterval * (config.session.rotationFraction || 0.5);
    const needsRotation = now - lastUpdated > rotateThreshold;

    metadata.lastActive = new Date().toISOString();
    metadata.lastActiveIp = ipAddress;

    if (needsRotation) {
      const newSessionToken = await generateSessionToken(config);
      if (!newSessionToken.success) return newSessionToken;

      const newCsrfToken = await generateCsrfToken(config);
      if (!newCsrfToken.success) return newCsrfToken;

      metadata.rotations = ((metadata.rotations as number) || 0) + 1;
      metadata.lastRotatedAt = new Date().toISOString();

      const updated = await prisma.session.update({
        where: { id: session.id },
        data: {
          tokenHash: newSessionToken.data.hash,
          csrfTokenHash: newCsrfToken.data.hash,
          expiresAt: addTime(
            new Date(),
            config.session.absoluteMaxLifetimeSeconds,
            "s",
          ),
          metadata: metadata as Prisma.InputJsonValue,
        },
        include: {
          user: {
            include: {
              userRoles: { include: { role: true } },
            },
          },
        },
      });

      const sessionCookie = createSessionCookie(
        newSessionToken.data.token,
        config,
      );
      const csrfCookie = createCsrfCookie(newCsrfToken.data.token, config);

      return success({
        isValid: true,
        state: SessionState.ACTIVE,
        session: updated,
        rotated: true,
        sessionToken: newSessionToken.data.token,
        csrfToken: newCsrfToken.data.token,
        sessionCookie,
        csrfCookie,
      });
    }

    await prisma.session.update({
      where: { id: session.id },
      data: {
        metadata: metadata as Prisma.InputJsonValue,
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
 * Revokes a single session
 */
export const revokeSession = createOperation(
  "revokeSession",
  ErrorCode.SESSION_REVOKED,
  "Failed to revoke session",
)(
  async (
    prisma: PrismaClient,
    sessionId: string,
    reason = "user_logout",
  ): Promise<AegisResponse<boolean>> => {
    await revokeSessionWithReason(prisma, sessionId, reason);
    return success(true);
  },
);

/**
 * Revokes all sessions for a user (optionally skipping one session)
 */
export const revokeAllUserSessions = createOperation(
  "revokeAllUserSessions",
  ErrorCode.SESSION_REVOKED,
  "Failed to revoke user sessions",
)(
  async (
    prisma: PrismaClient,
    userId: string,
    reason = "user_logout_all",
    exceptSessionId?: string,
  ): Promise<AegisResponse<number>> => {
    const whereClause: Prisma.SessionWhereInput = {
      userId,
      isRevoked: false,
    };
    if (exceptSessionId) {
      whereClause.id = { not: exceptSessionId };
    }

    const sessions = await prisma.session.findMany({
      where: whereClause,
      select: { id: true },
    });

    for (const s of sessions) {
      await revokeSessionWithReason(prisma, s.id, reason);
    }

    return success(sessions.length);
  },
);
