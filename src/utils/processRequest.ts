import type { Prisma, PrismaClient } from "@prisma/client";
import { signSessionToken, verifyCsrfToken } from "../security";
import type { AegisAuthConfig } from "../types";
import type { AegisContext, AuthenticatedUser, Endpoints } from "../types";
import { getCsrfToken, getSessionToken } from "./cookies";

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
): Promise<AegisContext> {
  try {
    const { ipAddress, userAgent, csrfToken, sessionToken } = getHeaders(
      headers,
      config,
    );
    let isAuthenticated = false;
    let user: AuthenticatedUser | null = null;
    let session: Prisma.SessionGetPayload<{
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

    if (!sessionToken) {
      return createContext({
        prisma,
        config,
        endpoints,
        headers,
        ipAddress,
        userAgent,
        csrfToken,
      });
    }

    const tokenHash = await signSessionToken({ sessionToken, config });
    session = (await prisma.session.findUnique({
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
      return createContext({
        prisma,
        config,
        endpoints,
        headers,
        ipAddress,
        userAgent,
        csrfToken,
      });
    }

    if (config.csrf.enabled) {
      const isCsrfValid = await verifyCsrfToken({
        token: csrfToken || "",
        hash: session.csrfTokenHash,
        config,
      });

      if (!isCsrfValid) {
        config.logger?.warn("Invalid CSRF token", { ipAddress, sessionToken });
        throw new Error("Invalid CSRF token");
      }
    }

    const userResult = session.user;
    if (!userResult || userResult.isBanned) {
      config.logger?.warn("User not found or banned", {
        ipAddress,
        userId: session.userId,
      });
      return createContext({
        prisma,
        config,
        endpoints,
        headers,
        ipAddress,
        userAgent,
        csrfToken,
      });
    }

    const { passwordHash, userRoles, ...safeUser } = userResult;
    const roles = userRoles.map((ur) => ur.role.name);
    const permissions = Array.from(
      new Set(userRoles.flatMap((ur) => ur.role.permissions || [])),
    );

    user = {
      ...safeUser,
      roles,
      permissions,
      sessions: userResult.sessions,
      passwordHistory: userResult.passwordHistory,
    };
    isAuthenticated = true;

    return createContext({
      prisma,
      config,
      endpoints,
      headers,
      ipAddress,
      userAgent,
      csrfToken,
      isAuthenticated,
      user,
      session,
    });
  } catch (error) {
    config.logger?.error("Error processing request", {
      error: error instanceof Error ? error.message : "Unknown error",
      ipAddress:
        headers.get("x-forwarded-for")?.split(",")[0].trim() ||
        headers.get("x-real-ip"),
    });
    throw error;
  }
}
