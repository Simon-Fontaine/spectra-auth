import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaUser,
} from "../types";
import { unbanUserSchema } from "../validations";

export async function unbanUser(
  context: CoreContext,
  input: { userId: string },
): Promise<ActionResponse> {
  const { prisma, config } = context;

  try {
    const validatedInput = unbanUserSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", { route: "unbanUser" });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { userId } = validatedInput.data;

    const user = (await prisma.user.findUnique({
      where: { id: userId },
    })) as PrismaUser | null;

    if (!user) {
      config.logger.securityEvent("USER_NOT_FOUND", {
        route: "unbanUser",
        userId,
      });
      return {
        success: false,
        status: 404,
        message: "User not found",
        code: ErrorCodes.USER_NOT_FOUND,
      };
    }

    await prisma.user.update({
      where: { id: userId },
      data: {
        isBanned: false,
      },
    });

    config.logger.securityEvent("USER_UNBANNED", { userId });

    return {
      success: true,
      status: 200,
      message: "User unbanned successfully",
    };
  } catch (error) {
    config.logger.error("Error unbanning user", { error: String(error) });
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
