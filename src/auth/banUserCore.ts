import { z } from "zod";
import { type ActionResponse, type CoreContext, ErrorCodes } from "../types";
import { getSessionCore } from "./getSessionCore";
import { userHasPermission, userHasRole } from "./permissions";

const BAN_PERMISSION = "BAN_USER";
const ADMIN_ROLE = "ADMIN";

const schema = z.object({
  userId: z.string().uuid("Invalid user ID provided."),
});

export async function banUserCore(
  ctx: CoreContext,
  options: { userId: string },
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest || {};

  logger?.info("banUserCore called", {
    ip: ipAddress,
    userId: options.userId,
  });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("banUserCore invalid input", {
        errors: parsed.error.errors,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid user ID provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }

    const sessionResult = await getSessionCore(ctx, { disableRefresh: true });
    if (!sessionResult.success || !sessionResult.data?.session) {
      return sessionResult;
    }

    const canBan = await userHasPermission(ctx, BAN_PERMISSION);
    const isAdmin = await userHasRole(ctx, ADMIN_ROLE);

    if (!canBan && !isAdmin) {
      logger?.warn("banUserCore insufficient permissions", {
        ip: ipAddress,
        userId: sessionResult.data.user?.id,
      });
      return {
        success: false,
        status: 403,
        message: "You do not have permission to ban users",
        code: ErrorCodes.AUTH_INSUFFICIENT_PERMISSIONS,
      };
    }

    const { userId } = parsed.data;

    const targetUser = await prisma.user.findUnique({
      where: { id: userId },
    });

    if (!targetUser) {
      logger?.warn("banUserCore target user not found", {
        userId,
        ip: ipAddress,
      });
      return {
        success: false,
        status: 404,
        message: "User not found",
        code: ErrorCodes.ACCOUNT_NOT_FOUND,
      };
    }

    await prisma.user.update({
      where: { id: userId },
      data: { isBanned: true },
    });

    logger?.info("banUserCore success", {
      adminUserId: sessionResult.data.user?.id,
      userId,
      ip: ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: `User ${userId} has been banned.`,
    };
  } catch (error) {
    logger?.error("banUserCore error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while banning the user",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
