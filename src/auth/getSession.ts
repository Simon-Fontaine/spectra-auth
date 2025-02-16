import {
  type ActionResponse,
  type ClientSession,
  type ClientUser,
  type CoreContext,
  ErrorCodes,
  type PrismaUser,
} from "../types";
import { transformUser } from "../utils";
import { validateAndRotateSession } from "./validateAndRotateSession";
import { validateSession } from "./validateSession";

export async function getSession(
  ctx: CoreContext,
  options?: { disableRefresh?: boolean },
): Promise<
  ActionResponse<{
    session?: ClientSession;
    user?: ClientUser;
    roles?: string[];
  }>
> {
  const { parsedRequest, prisma } = ctx;
  const { sessionToken } = parsedRequest || {};

  try {
    if (!sessionToken) {
      return {
        success: false,
        status: 401,
        message: "No session token provided",
        code: ErrorCodes.SESSION_NOT_FOUND,
      };
    }

    let sessionResult: ActionResponse<{ session?: ClientSession }> | undefined;

    if (options?.disableRefresh) {
      sessionResult = await validateSession(ctx);
    } else {
      sessionResult = await validateAndRotateSession(ctx);
    }

    if (!sessionResult.success || !sessionResult.data?.session) {
      return sessionResult;
    }

    const session = sessionResult.data.session;

    const user = (await prisma.user.findUnique({
      where: { id: session.userId },
    })) as PrismaUser | null;

    if (!user) {
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

    return {
      success: true,
      status: 200,
      message: "Session found",
      data: {
        session,
        user: transformUser({ user }),
        roles,
      },
    };
  } catch (error) {
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while getting the session",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
