import type { Prisma, PrismaClient } from "@prisma/client";
import { generateCsrfToken } from "../security/csrfToken";
import {
  generateSessionToken,
  signSessionToken,
} from "../security/sessionToken";
import type { AegisAuthConfig, SessionDevice, SessionLocation } from "../types";
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

  const expiresAt = new Date(
    Date.now() + config.session.absoluteMaxLifetimeSeconds * 1000,
  );

  // Generate browser fingerprint if enabled
  let fingerprint: string | undefined;
  if (config.session.fingerprintOptions?.enabled && headers) {
    const fingerprintResp = await generateBrowserFingerprint({
      ip: ipAddress,
      userAgent: deviceData?.userAgent || undefined,
      headers,
      config,
    });

    if (fingerprintResp.success) {
      fingerprint = fingerprintResp.data;
    }
  }

  const session = await prisma.session.create({
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
      deviceData,
      locationData,
      metadata: fingerprint ? { fingerprint } : undefined,
    },
  });

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
  const signResp = await signSessionToken({
    sessionToken: currentSessionToken,
    config,
  });
  if (!signResp.success) {
    throw new Error(signResp.error.message);
  }
  const tokenHash = signResp.data;

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

  if (!session || session.isRevoked || session.expiresAt <= new Date()) {
    throw new Error("Invalid or expired session");
  }

  // Check for idle timeout if configured
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

  // Validate fingerprint if enabled
  if (config.session.fingerprintOptions?.enabled && headers) {
    // Get stored fingerprint from session metadata
    const sessionMetadata = session.metadata as Record<string, any> | null;
    const storedFingerprint = sessionMetadata?.fingerprint;

    // Generate current fingerprint
    const fingerprintResp = await generateBrowserFingerprint({
      ip: session.ipAddress || undefined,
      userAgent: (session.deviceData as SessionDevice | null)?.userAgent,
      headers,
      config,
    });

    if (fingerprintResp.success) {
      const currentFingerprint = fingerprintResp.data;

      // No fingerprint stored yet but one is now available
      if (
        !storedFingerprint &&
        !config.session.fingerprintOptions.strictValidation
      ) {
        // Update session with new fingerprint
        await prisma.session.update({
          where: { id: session.id },
          data: {
            metadata: {
              ...sessionMetadata,
              fingerprint: currentFingerprint,
            },
          },
        });
      }
      // Validate existing fingerprint
      else if (storedFingerprint && storedFingerprint !== currentFingerprint) {
        if (config.session.fingerprintOptions.strictValidation) {
          // In strict mode, revoke the session and throw error
          await prisma.session.update({
            where: { id: session.id },
            data: { isRevoked: true },
          });
          throw new Error("Session fingerprint mismatch");
        }
        // In non-strict mode we just log the mismatch but allow the session
        config.logger?.warn("Session fingerprint mismatch detected", {
          sessionId: session.id,
          userId: session.userId,
        });
      }
    }
  }

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
    // Session rotation logic
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

    // Use transaction to update session
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

// Other existing functions remain unchanged
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

export function getClearSessionCookies(config: AegisAuthConfig): {
  sessionCookie: string;
  csrfCookie: string;
} {
  const sessionCookie = clearSessionCookie(config);
  const csrfCookie = clearCsrfCookie(config);
  return { sessionCookie, csrfCookie };
}
