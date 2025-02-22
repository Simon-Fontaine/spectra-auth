import type { Prisma, PrismaClient } from "@prisma/client";
import { signSessionToken, verifyCsrfToken } from "../security";
import type { AegisAuthConfig } from "../types";
import type {
  AegisContext,
  AegisResponse,
  AuthenticatedUser,
  Endpoints,
} from "../types";
import { getCsrfToken, getSessionToken } from "./cookies";
import { fail, success } from "./response";

interface RequestHeaders {
  ipAddress?: string;
  userAgent?: string;
  csrfToken?: string;
  sessionToken?: string;
}

function getHeaders(headers: Headers, config: AegisAuthConfig): RequestHeaders {
  return {
    ipAddress:
      headers.get("x-forwarded-for")?.split(",")[0].trim() ||
      headers.get("x-real-ip") ||
      undefined,
    userAgent: headers.get("user-agent") || undefined,
    csrfToken: config.csrf.enabled ? getCsrfToken(headers, config) : undefined,
    sessionToken: getSessionToken(headers, config),
  };
}

interface ContextParams {
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
}: ContextParams): AegisContext {
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
): Promise<AegisResponse<AegisContext>> {
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

    const hashResp = await signSessionToken({ sessionToken, config });
    if (!hashResp.success) {
      return fail(hashResp.error.code, hashResp.error.message);
    }

    const tokenHash = hashResp.data;
    const session = (await prisma.session.findUnique({
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
    })) as Prisma.SessionGetPayload<{
      include: {
        user: {
          include: {
            userRoles: { include: { role: true } };
            sessions: true;
            passwordHistory: true;
          };
        };
      };
    }> | null;

    if (!session || session.isRevoked || session.expiresAt <= new Date()) {
      config.logger?.debug("Invalid or expired session", { ipAddress });
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

    if (config.csrf.enabled) {
      const csrfResp = await verifyCsrfToken({
        token: csrfToken || "",
        hash: session.csrfTokenHash,
        config,
      });
      if (!csrfResp.success) {
        return fail(
          csrfResp.error.code || "INVALID_CSRF_TOKEN",
          csrfResp.error.message || "CSRF token verification failed",
        );
      }
      const isCsrfValid = csrfResp.data;
      if (!isCsrfValid) {
        config.logger?.warn("Invalid CSRF token", { ipAddress, sessionToken });
        return fail("INVALID_CSRF_TOKEN", "Invalid CSRF token");
      }
    }

    const userResult = session.user;
    if (!userResult || userResult.isBanned) {
      config.logger?.warn("User not found or banned", {
        ipAddress,
        userId: session.userId,
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

    const authUser: AuthenticatedUser = {
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
      csrfToken,
      isAuthenticated: true,
      user: authUser,
      session,
    });
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
