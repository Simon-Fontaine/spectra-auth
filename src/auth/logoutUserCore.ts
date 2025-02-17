import { type ActionResponse, type CoreContext, ErrorCodes } from "../types";
import { getSessionCore } from "./getSessionCore";

export async function logoutUserCore(
  ctx: CoreContext,
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config } = ctx;
  const { logger } = config;
  const { sessionToken, ipAddress } = parsedRequest || {};

  logger?.info("logoutUser called", { ip: ipAddress });

  try {
    const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
    if (!sessionResult.success || !sessionResult.data?.session) {
      return sessionResult;
    }
    const { session } = sessionResult.data;

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
