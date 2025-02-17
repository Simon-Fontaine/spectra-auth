import {
  type ActionResponse,
  type ClientSession,
  type ClientUser,
  type CoreContext,
  ErrorCodes,
  type PrismaUser,
} from "../types";
import { transformUser } from "../utils";
import { validateAndRotateSessionCore } from "./validateAndRotateSessionCore";
import { validateSessionCore } from "./validateSessionCore";

export async function getSessionCore(
  ctx: CoreContext,
  options?: { disableRefresh?: boolean },
): Promise<
  ActionResponse<{
    session?: ClientSession;
    user?: ClientUser;
    roles?: string[];
    permissions?: string[];
  }>
> {
  const { parsedRequest, prisma, config } = ctx;
  const { logger } = config;
  const { sessionToken, ipAddress } = parsedRequest || {};

  logger?.info("getSession called", { ip: ipAddress });

  try {
    if (!sessionToken) {
      logger?.warn("getSession no session token", { ip: ipAddress });
      return {
        success: false,
        status: 401,
        message: "No session token provided",
        code: ErrorCodes.SESSION_NOT_FOUND,
      };
    }

    let sessionResult: ActionResponse<{ session?: ClientSession }>;
    if (options?.disableRefresh) {
      sessionResult = await validateSessionCore(ctx);
    } else {
      sessionResult = await validateAndRotateSessionCore(ctx);
    }

    if (!sessionResult.success || !sessionResult.data?.session) {
      logger?.warn("getSession validation failed", {
        ip: ipAddress,
        reason: sessionResult.message,
      });
      return sessionResult;
    }

    const session = sessionResult.data.session;
    const user = (await prisma.user.findUnique({
      where: { id: session.userId },
    })) as PrismaUser | null;

    if (!user) {
      logger?.warn("getSession user not found", {
        userId: session.userId,
        ip: ipAddress,
      });
      return {
        success: false,
        status: 401,
        message: "User not found",
        code: ErrorCodes.ACCOUNT_NOT_FOUND,
      };
    }

    const userRoles = await prisma.userRoles.findMany({
      where: { userId: user.id },
      include: { role: true },
    });
    const roles = userRoles.map((userRole) => userRole.role.name);
    const permissionsSet = new Set<string>();
    for (const ur of userRoles) {
      if (ur.role.permissions) {
        for (const perm of ur.role.permissions) {
          permissionsSet.add(perm);
        }
      }
    }
    const permissions = Array.from(permissionsSet);

    logger?.info("getSession success", { userId: user.id, ip: ipAddress });

    return {
      success: true,
      status: 200,
      message: "Session found",
      data: {
        session,
        user: transformUser({ user }),
        roles,
        permissions,
      },
    };
  } catch (error) {
    logger?.error("getSession error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while getting the session",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
