import type { Prisma, PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { signSessionToken, verifyCsrfToken } from "../security";
import type { AegisContext, AuthenticatedUser, Endpoints } from "../types";
import { getCsrfToken, getSessionToken } from "./cookies";

export async function processRequest(
  prisma: PrismaClient,
  config: AegisAuthConfig,
  endpoints: Endpoints,
  headers: Headers,
): Promise<AegisContext> {
  let isAuthenticated = false;
  let user: AuthenticatedUser | null = null;
  let session: Prisma.SessionGetPayload<true> | null = null;

  const ipAddress =
    headers.get("x-forwarded-for")?.split(",")[0].trim() ||
    headers.get("x-real-ip") ||
    undefined;
  const userAgent = headers.get("user-agent") || undefined;
  const csrfToken = config.csrf.enabled
    ? getCsrfToken(headers, config)
    : undefined;
  const sessionToken = getSessionToken(headers, config);

  if (sessionToken) {
    const tokenHash = await signSessionToken({ sessionToken, config });
    session = await prisma.session.findUnique({
      where: { tokenHash },
    });

    if (session && !session.isRevoked && session.expiresAt > new Date()) {
      if (config.csrf.enabled) {
        const isCsrfValid = await verifyCsrfToken({
          token: csrfToken || "",
          hash: session.csrfTokenHash,
          config,
        });

        if (!isCsrfValid) {
          config.logger?.warn("Invalid CSRF token", {
            ipAddress,
            sessionToken,
          });
          throw new Error("Invalid CSRF token");
        }

        const userResult = await prisma.user.findUnique({
          where: { id: session.userId },
          include: {
            userRoles: { include: { role: true } },
            sessions: true,
            passwordHistory: true,
          },
        });

        if (userResult && !userResult.isBanned) {
          isAuthenticated = true;
          const { passwordHash, userRoles, ...safeUser } = userResult;

          const roles = userRoles.map((ur) => ur.role.name);
          const permissionsSet = new Set<string>();
          for (const ur of userRoles) {
            if (ur.role.permissions) {
              for (const perm of ur.role.permissions) {
                permissionsSet.add(perm);
              }
            }
          }
          const permissions = Array.from(permissionsSet);
          user = {
            ...safeUser,
            roles,
            permissions,
            sessions: userResult.sessions,
            passwordHistory: userResult.passwordHistory,
          };
        }
      }
    }
  }

  const context: AegisContext = {
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

  return context;
}
