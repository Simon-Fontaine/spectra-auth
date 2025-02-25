import type { Prisma, PrismaClient } from "@prisma/client";
import { generateCsrfToken } from "../security/csrfToken";
import {
  generateSessionToken,
  signSessionToken,
} from "../security/sessionToken";
import type {
  AegisAuthConfig,
  SessionDevice,
  SessionLocation,
  SessionMetadata,
} from "../types";
import {
  clearCsrfCookie,
  clearSessionCookie,
  createCsrfCookie,
  createSessionCookie,
} from "./cookies";
import { generateBrowserFingerprint } from "./fingerprint";

export async function createSession(
  prisma: PrismaClient,
  config: AegisAuthConfig,
  userId: string,
  ipAddress?: string,
  locationData?: SessionLocation,
  deviceData?: SessionDevice,
  headers?: Headers,
): Promise<{
  session: Prisma.SessionGetPayload<{
    include: {
      user: {
        include: {
          userRoles: { include: { role: true } };
          sessions: true;
          passwordHistory: true;
        };
      };
    };
  }>;
  sessionToken: string;
  csrfToken: string;
  sessionCookie: string;
  csrfCookie: string;
}> {
  // Generate tokens first
  const sessionTokenResp = await generateSessionToken({ config });
  if (!sessionTokenResp.success) {
    throw new Error(sessionTokenResp.error.message);
  }
  const { sessionToken, sessionTokenHash } = sessionTokenResp.data;

  const csrfTokenResp = await generateCsrfToken({ config });
  if (!csrfTokenResp.success) {
    throw new Error(csrfTokenResp.error.message);
  }
  const { csrfToken, csrfTokenHash } = csrfTokenResp.data;

  // Enforce session expiration
  const expiresAt = new Date(
    Date.now() + config.session.absoluteMaxLifetimeSeconds * 1000,
  );

  // Build metadata object
  const metadata: Record<string, unknown> = {};

  if (locationData) {
    metadata.location = locationData;
  }

  if (deviceData) {
    metadata.device = deviceData;
  }

  // Generate browser fingerprint if enabled and headers are available
  if (config.session.fingerprintOptions?.enabled && headers) {
    const fingerprintResp = await generateBrowserFingerprint({
      ip: ipAddress,
      userAgent: deviceData?.userAgent || undefined,
      headers,
      config,
    });

    if (fingerprintResp.success) {
      metadata.fingerprint = fingerprintResp.data;
    }
  }

  // Create session within a transaction for atomicity
  const session = await prisma.$transaction(async (tx) => {
    // Enforce maximum session limit if configured
    if (config.account.maxSimultaneousSessions > 0) {
      const existingSessions = await tx.session.findMany({
        where: {
          userId,
          isRevoked: false,
        },
        orderBy: {
          createdAt: "asc",
        },
      });

      const sessionCount = existingSessions.length;
      if (sessionCount >= config.account.maxSimultaneousSessions) {
        // Get oldest sessions to revoke
        const sessionsToRevoke = existingSessions.slice(
          0,
          sessionCount - config.account.maxSimultaneousSessions + 1,
        );

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
            userRoles: { include: { role: true } },
            sessions: true,
            passwordHistory: true,
          },
        },
      },
      data: {
        userId,
        tokenHash: sessionTokenHash,
        csrfTokenHash,
        expiresAt,
        ipAddress,
        metadata:
          Object.keys(metadata).length > 0
            ? (metadata as Prisma.InputJsonValue)
            : undefined,
      },
    });
  });

  // Create cookies
  const sessionCookie = createSessionCookie(sessionToken, config);
  const csrfCookie = createCsrfCookie(csrfToken, config);

  return { session, sessionToken, csrfToken, sessionCookie, csrfCookie };
}

export interface SessionValidationResult {
  session: Prisma.SessionGetPayload<{
    include: {
      user: {
        include: {
          userRoles: { include: { role: true } };
          sessions: true;
          passwordHistory: true;
        };
      };
    };
  }>;
  rotated: boolean;
  sessionToken: string;
  csrfToken: string;
  sessionCookie: string;
  csrfCookie: string;
}

export async function validateAndRotateSession(
  prisma: PrismaClient,
  config: AegisAuthConfig,
  currentSessionToken: string,
  headers?: Headers,
): Promise<SessionValidationResult> {
  // Generate token hash for lookup
  const signResp = await signSessionToken({
    sessionToken: currentSessionToken,
    config,
  });
  if (!signResp.success) {
    throw new Error(signResp.error.message);
  }
  const tokenHash = signResp.data;

  // Fetch session with a single query (including user data)
  const session = await prisma.session.findUnique({
    where: { tokenHash },
    include: {
      user: {
        include: {
          userRoles: { include: { role: true } },
          sessions: true,
          passwordHistory: true,
        },
      },
    },
  });

  // Basic session validations
  if (!session) {
    throw new Error("Session not found");
  }

  if (session.isRevoked) {
    throw new Error("Session has been revoked");
  }

  if (session.expiresAt <= new Date()) {
    // Automatically revoke expired sessions
    await prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true },
    });
    throw new Error("Session has expired");
  }

  // Idle timeout check
  if (config.session.idleTimeoutSeconds) {
    const lastActivity = session.updatedAt.getTime();
    const now = Date.now();
    const idleTimeoutMs = config.session.idleTimeoutSeconds * 1000;

    if (now - lastActivity > idleTimeoutMs) {
      await prisma.session.update({
        where: { id: session.id },
        data: { isRevoked: true },
      });
      throw new Error("Session expired due to inactivity");
    }
  }

  // Fingerprint validation
  if (config.session.fingerprintOptions?.enabled && headers) {
    const sessionMetadata =
      (session.metadata as Record<string, unknown> | null) || {};
    const storedFingerprint = sessionMetadata?.fingerprint as
      | string
      | undefined;
    const deviceData = sessionMetadata?.device as SessionDevice | undefined;

    const fingerprintResp = await generateBrowserFingerprint({
      ip: session.ipAddress || undefined,
      userAgent: deviceData?.userAgent || undefined,
      headers,
      config,
    });

    if (fingerprintResp.success) {
      const currentFingerprint = fingerprintResp.data;

      // Handle fingerprint validation
      if (!storedFingerprint) {
        // No fingerprint stored yet but one is now available
        if (!config.session.fingerprintOptions.strictValidation) {
          // Update session with new fingerprint
          await prisma.session.update({
            where: { id: session.id },
            data: {
              metadata: {
                ...sessionMetadata,
                fingerprint: currentFingerprint,
              } as Prisma.InputJsonValue,
            },
          });
        }
      } else if (storedFingerprint !== currentFingerprint) {
        // Fingerprint mismatch
        if (config.session.fingerprintOptions.strictValidation) {
          // In strict mode, revoke the session and throw error
          await prisma.session.update({
            where: { id: session.id },
            data: { isRevoked: true },
          });
          throw new Error("Session fingerprint mismatch");
        }
        // In non-strict mode we log the mismatch but allow the session
        config.logger?.warn("Session fingerprint mismatch detected", {
          sessionId: session.id,
          userId: session.userId,
        });
      }
    }
  }

  // Check if session needs rotation
  const lastUpdated = session.updatedAt.getTime();
  const now = Date.now();
  const refreshIntervalMs = config.session.refreshIntervalSeconds * 1000;
  const rotationThreshold =
    refreshIntervalMs * (config.session.rotationFraction ?? 0.5);

  let rotated = false;
  let newSessionToken = currentSessionToken;
  let newCsrfToken = "";
  let newSessionCookie = "";
  let newCsrfCookie = "";

  if (now - lastUpdated > rotationThreshold) {
    // Generate new tokens for rotation
    const newSessionResp = await generateSessionToken({ config });
    if (!newSessionResp.success) {
      throw new Error(newSessionResp.error.message);
    }
    const { sessionToken: rotatedToken, sessionTokenHash: rotatedTokenHash } =
      newSessionResp.data;

    const newCsrfResp = await generateCsrfToken({ config });
    if (!newCsrfResp.success) {
      throw new Error(newCsrfResp.error.message);
    }
    const { csrfToken: rotatedCsrf, csrfTokenHash: rotatedCsrfHash } =
      newCsrfResp.data;

    // Use transaction to update session atomically
    const updatedSession = await prisma.$transaction(async (tx) => {
      return tx.session.update({
        where: { id: session.id },
        include: {
          user: {
            include: {
              userRoles: { include: { role: true } },
              sessions: true,
              passwordHistory: true,
            },
          },
        },
        data: {
          tokenHash: rotatedTokenHash,
          csrfTokenHash: rotatedCsrfHash,
          expiresAt: new Date(
            Date.now() + config.session.absoluteMaxLifetimeSeconds * 1000,
          ),
        },
      });
    });

    newSessionToken = rotatedToken;
    newCsrfToken = rotatedCsrf;
    newSessionCookie = createSessionCookie(rotatedToken, config);
    newCsrfCookie = createCsrfCookie(rotatedCsrf, config);
    rotated = true;

    config.logger?.debug("Session rotated", {
      sessionId: session.id,
      userId: session.userId,
    });

    return {
      session: updatedSession,
      rotated,
      sessionToken: newSessionToken,
      csrfToken: newCsrfToken,
      sessionCookie: newSessionCookie,
      csrfCookie: newCsrfCookie,
    };
  }

  // No rotation needed, just refresh the session's last activity time
  await prisma.session.update({
    where: { id: session.id },
    data: { updatedAt: new Date() },
  });

  return {
    session,
    rotated: false,
    sessionToken: currentSessionToken,
    csrfToken: "",
    sessionCookie: createSessionCookie(currentSessionToken, config),
    csrfCookie: "",
  };
}

export async function revokeSession(
  prisma: PrismaClient,
  sessionId: string,
): Promise<boolean> {
  const session = await prisma.session.update({
    where: { id: sessionId },
    data: { isRevoked: true },
  });
  return session.isRevoked;
}

export async function revokeAllUserSessions(
  prisma: PrismaClient,
  userId: string,
  exceptSessionId?: string,
): Promise<number> {
  const whereClause: Prisma.SessionWhereInput = {
    userId,
    isRevoked: false,
  };

  if (exceptSessionId) {
    whereClause.id = { not: exceptSessionId };
  }

  const result = await prisma.session.updateMany({
    where: whereClause,
    data: { isRevoked: true },
  });

  return result.count;
}

export function getClearSessionCookies(config: AegisAuthConfig): {
  sessionCookie: string;
  csrfCookie: string;
} {
  const sessionCookie = clearSessionCookie(config);
  const csrfCookie = clearCsrfCookie(config);
  return { sessionCookie, csrfCookie };
}

export function getSessionMetadata(
  session: Prisma.SessionGetPayload<true>,
): SessionMetadata {
  return (session.metadata as SessionMetadata | null) || {};
}

export function getSessionLocation(
  session: Prisma.SessionGetPayload<true>,
): SessionLocation | undefined {
  return getSessionMetadata(session).location;
}

export function getSessionDevice(
  session: Prisma.SessionGetPayload<true>,
): SessionDevice | undefined {
  return getSessionMetadata(session).device;
}

export function getSessionFingerprint(
  session: Prisma.SessionGetPayload<true>,
): string | undefined {
  return getSessionMetadata(session).fingerprint as string | undefined;
}
