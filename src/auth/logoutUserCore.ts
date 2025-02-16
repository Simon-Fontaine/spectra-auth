import { signSessionToken } from "../security";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaSession,
} from "../types";

export async function logoutUserCore(
  ctx: CoreContext,
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config } = ctx;
  const { logger } = config;
  const { sessionToken, ipAddress } = parsedRequest || {};

  logger?.info("logoutUser called", { ip: ipAddress });

  try {
    if (!sessionToken) {
      logger?.warn("logoutUser no session token", { ip: ipAddress });
      return {
        success: false,
        status: 401,
        message: "No session token provided",
        code: ErrorCodes.SESSION_NOT_FOUND,
      };
    }

    const tokenHash = await signSessionToken({ sessionToken, config });
    const session = (await prisma.session.findUnique({
      where: { tokenHash },
    })) as PrismaSession | null;

    if (!session) {
      logger?.warn("logoutUser invalid token", { ip: ipAddress });
      return {
        success: false,
        status: 401,
        message: "Invalid session token",
        code: ErrorCodes.SESSION_INVALID,
      };
    }

    await prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true },
    });

    logger?.info("logoutUser success", {
      userId: session.userId,
      ip: ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: "User logged out successfully",
    };
  } catch (error) {
    logger?.error("logoutUser error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while logging out the user",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
