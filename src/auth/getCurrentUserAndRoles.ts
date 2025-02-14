import { validateAndRotateSession } from "../actions";
import { createCsrfCookie, createSessionCookie } from "../cookies";
import { verifyCsrfToken } from "../security";
import type {
  ActionResponse,
  ClientSession,
  CoreContext,
  PrismaUser,
} from "../types";

export async function getCurrentUserAndRolesCore(
  context: CoreContext,
  options: {
    csrfCheck?: boolean;
    alwaysSetCookie?: boolean;
  },
): Promise<
  ActionResponse<{
    session?: ClientSession;
    user?: PrismaUser;
    roles?: string[];
  }>
> {
  const { prisma, config, parsedRequest } = context;
  const { sessionToken, csrfToken, rawRequest } = parsedRequest ?? {};

  try {
    if (!sessionToken) {
      return {
        success: false,
        status: 401,
        message: "No session token provided",
      };
    }

    const sessionResult = await validateAndRotateSession(context, {
      sessionToken,
    });

    if (!sessionResult.success || !sessionResult.data?.session) {
      return sessionResult;
    }

    const headers = new Headers();
    if (sessionResult.data.rolled || options?.alwaysSetCookie) {
      const sessionCookie = createSessionCookie({
        sessionToken: sessionResult.data.session.sessionToken,
        config: config,
      });
      headers.append("Set-Cookie", sessionCookie);

      // If CSRF is enabled globally, also set the CSRF cookie
      if (config.csrf.enabled) {
        const csrfCookie = createCsrfCookie({
          csrfToken: sessionResult.data.session.csrfToken,
          config: config,
        });
        headers.append("Set-Cookie", csrfCookie);
      }
    }

    const session = sessionResult.data.session;

    // 3. CSRF check if desired
    if (options?.csrfCheck) {
      const method = (
        rawRequest?.headers.get?.("method") || "POST"
      ).toUpperCase();
      // or however you want to pass the request method
      if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
        const csrfTokenFromRequest = csrfToken;
        if (!csrfTokenFromRequest) {
          return {
            success: false,
            status: 403,
            message: "CSRF token missing",
          };
        }
        const isValidCsrf = await verifyCsrfToken({
          token: csrfTokenFromRequest,
          hash: session.csrfToken,
          config: config,
        });
        if (!isValidCsrf) {
          return {
            success: false,
            status: 403,
            message: "Invalid CSRF token",
          };
        }
      }
    }

    // 4. Load the user from the DB
    const user = await prisma.user.findUnique({
      where: { id: session.userId },
    });
    if (!user) {
      return {
        success: false,
        status: 404,
        message: "User not found",
      };
    }

    const userRoles = await prisma.userRoles.findMany({
      where: { userId: user.id },
      include: { role: true },
    });
    const roleNames = userRoles.map((ur) => ur.role.name);

    return {
      success: true,
      status: 200,
      message: "Session & User loaded",
      data: {
        session,
        user,
        roles: roleNames,
      },
    };
  } catch (error) {
    config.logger.error("Error fetching current user & roles", {
      error: String(error),
    });
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
    };
  }
}
