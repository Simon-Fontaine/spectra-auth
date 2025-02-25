import type { Prisma, PrismaClient } from "@prisma/client";
import { verifyCsrfToken } from "../security";
import type {
  AegisAuthConfig,
  AegisContext,
  AegisResponse,
  AuthenticatedUser,
  Endpoints,
} from "../types";
import { getCsrfToken, getSessionToken } from "./cookies";
import { extractClientIP } from "./ip";
import { fail, success } from "./response";
import {
  type SessionValidationResult,
  validateAndRotateSession,
} from "./sessions";

function getHeaders(headers: Headers, config: AegisAuthConfig) {
  return {
    ipAddress: extractClientIP(headers, config),
    userAgent: headers.get("user-agent") || undefined,
    csrfToken: config.csrf.enabled ? getCsrfToken(headers, config) : undefined,
    sessionToken: getSessionToken(headers, config),
  };
}

interface ExtendedAegisContext extends AegisContext {
  cookies?: {
    sessionCookie: string;
    csrfCookie: string;
  };
}

function createContext({
  prisma,
  config,
  endpoints,
  headers,
  ipAddress,
  userAgent,
  csrfToken,
  isAuthenticated = false,
  user = null,
  session = null,
}: {
  prisma: PrismaClient;
  config: AegisAuthConfig;
  endpoints: Endpoints;
  headers: Headers;
  ipAddress?: string;
  userAgent?: string;
  csrfToken?: string;
  isAuthenticated?: boolean;
  user?: AuthenticatedUser | null;
  session?: Prisma.SessionGetPayload<true> | null;
}): ExtendedAegisContext {
  return {
    prisma,
    config,
    endpoints,
    req: {
      ipAddress,
      userAgent,
      csrfToken,
      headers,
    },
    auth: {
      isAuthenticated,
      user,
      session,
    },
  };
}

export async function processRequest(
  prisma: PrismaClient,
  config: AegisAuthConfig,
  endpoints: Endpoints,
  headers: Headers,
): Promise<AegisResponse<ExtendedAegisContext>> {
  const requestStartTime = Date.now();
  const requestId = Math.random().toString(36).substring(2, 15);

  try {
    const { ipAddress, userAgent, csrfToken, sessionToken } = getHeaders(
      headers,
      config,
    );

    config.logger?.debug("Processing request", {
      requestId,
      ipAddress,
      hasSessionToken: !!sessionToken,
      hasCsrfToken: !!csrfToken,
    });

    // Suspicious pattern: CSRF token without session
    if (!sessionToken && csrfToken && config.csrf.enabled) {
      config.logger?.warn("CSRF token without session detected", {
        requestId,
        ipAddress,
      });
      // Don't indicate the suspicious nature to the client
      const ctx = createContext({
        prisma,
        config,
        endpoints,
        headers,
        ipAddress,
        userAgent,
        csrfToken,
      });
      return success(ctx);
    }

    // No session token, return unauthenticated context
    if (!sessionToken) {
      const ctx = createContext({
        prisma,
        config,
        endpoints,
        headers,
        ipAddress,
        userAgent,
        csrfToken,
      });
      return success(ctx);
    }

    // Attempt to validate and potentially rotate the session
    let validationResult: SessionValidationResult;
    try {
      validationResult = await validateAndRotateSession(
        prisma,
        config,
        sessionToken,
        headers,
      );
    } catch (error) {
      config.logger?.debug("Session validation failed", {
        requestId,
        ipAddress,
        error: error instanceof Error ? error.message : String(error),
      });
      const ctx = createContext({
        prisma,
        config,
        endpoints,
        headers,
        ipAddress,
        userAgent,
        csrfToken,
      });
      return success(ctx);
    }

    // CSRF verification (if CSRF is enabled and session wasn't rotated)
    // If session was rotated, new CSRF token was already generated
    if (config.csrf.enabled && !validationResult.rotated) {
      const csrfResp = await verifyCsrfToken({
        token: csrfToken || "",
        hash: validationResult.session.csrfTokenHash,
        config,
      });

      if (!csrfResp.success || !csrfResp.data) {
        config.logger?.warn("CSRF validation failed", {
          requestId,
          ipAddress,
          sessionId: validationResult.session.id,
        });

        // Don't indicate the failure reason
        const ctx = createContext({
          prisma,
          config,
          endpoints,
          headers,
          ipAddress,
          userAgent,
          csrfToken,
        });
        return success(ctx);
      }
    }

    // User validation
    const userRecord = validationResult.session.user;

    // Check if user exists and is not banned
    if (!userRecord || userRecord.isBanned) {
      const reason = !userRecord ? "User not found" : "User banned";
      config.logger?.warn(`Session validation failed: ${reason}`, {
        requestId,
        ipAddress,
        sessionId: validationResult.session.id,
        userId: validationResult.session.userId,
      });

      // Return unauthenticated context without exposing the reason
      const ctx = createContext({
        prisma,
        config,
        endpoints,
        headers,
        ipAddress,
        userAgent,
        csrfToken,
      });
      return success(ctx);
    }

    // Process user data for auth context
    const { passwordHash, userRoles, ...safeUser } = userRecord;
    const roles = userRoles.map((ur) => ur.role.name);
    const permissions = Array.from(
      new Set(userRoles.flatMap((ur) => ur.role.permissions || [])),
    );

    const authUser = {
      ...safeUser,
      roles,
      permissions,
      sessions: userRecord.sessions,
      passwordHistory: userRecord.passwordHistory,
    };

    // Create authenticated context
    const ctx = createContext({
      prisma,
      config,
      endpoints,
      headers,
      ipAddress,
      userAgent,
      csrfToken: validationResult.rotated
        ? validationResult.csrfToken
        : csrfToken,
      isAuthenticated: true,
      user: authUser,
      session: validationResult.session,
    });

    // Add cookies if session was rotated
    if (validationResult.rotated) {
      (ctx as ExtendedAegisContext).cookies = {
        sessionCookie: validationResult.sessionCookie,
        csrfCookie: validationResult.csrfCookie,
      };
    }

    const processingTime = Date.now() - requestStartTime;
    config.logger?.debug("Request processing complete", {
      requestId,
      authenticated: true,
      processingTimeMs: processingTime,
    });

    return success(ctx);
  } catch (error) {
    const processingTime = Date.now() - requestStartTime;
    config.logger?.error("Request processing failed", {
      requestId,
      processingTimeMs: processingTime,
      error: error instanceof Error ? error.message : "Unknown error",
      ipAddress: extractClientIP(headers, config),
    });

    return fail("PROCESS_REQUEST_ERROR", "Error processing request");
  }
}
