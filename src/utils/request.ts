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
  try {
    const { ipAddress, userAgent, csrfToken, sessionToken } = getHeaders(
      headers,
      config,
    );

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

    let validationResult: SessionValidationResult;
    try {
      validationResult = await validateAndRotateSession(
        prisma,
        config,
        sessionToken,
        headers,
      );
    } catch (error) {
      config.logger?.debug("Session invalid or expired", { ipAddress });
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

    if (config.csrf.enabled && !validationResult.rotated) {
      const csrfResp = await verifyCsrfToken({
        token: csrfToken || "",
        hash: validationResult.session.csrfTokenHash,
        config,
      });
      if (!csrfResp.success || !csrfResp.data) {
        config.logger?.warn("Invalid CSRF token", { ipAddress, sessionToken });
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

    const userResult = validationResult.session.user;
    if (!userResult || userResult.isBanned) {
      config.logger?.warn("User not found or banned", {
        ipAddress,
        userId: validationResult.session.userId,
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

    const { passwordHash, userRoles, ...safeUser } = userResult;
    const roles = userRoles.map((ur) => ur.role.name);
    const permissions = Array.from(
      new Set(userRoles.flatMap((ur) => ur.role.permissions || [])),
    );
    const authUser = {
      ...safeUser,
      roles,
      permissions,
      sessions: userResult.sessions,
      passwordHistory: userResult.passwordHistory,
    };

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

    if (validationResult.rotated) {
      (ctx as ExtendedAegisContext).cookies = {
        sessionCookie: validationResult.sessionCookie,
        csrfCookie: validationResult.csrfCookie,
      };
    }

    return success(ctx);
  } catch (error) {
    config.logger?.error("Error processing request", {
      error: error instanceof Error ? error.message : "Unknown error",
      ipAddress:
        headers.get("x-forwarded-for")?.split(",")[0].trim() ||
        headers.get("x-real-ip"),
    });
    return fail("PROCESS_REQUEST_ERROR", "Error processing request");
  }
}
