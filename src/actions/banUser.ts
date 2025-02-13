import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { type ActionResponse, ErrorCodes, type PrismaUser } from "../types";
import { banUserSchema } from "../validations";

export async function banUser(
  context: { prisma: PrismaClient; config: AegisAuthConfig },
  input: { userId: string },
): Promise<ActionResponse> {
  const { prisma, config } = context;

  try {
    const validatedInput = banUserSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", { route: "banUser" });
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
        route: "banUser",
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
        isBanned: true,
      },
    });

    config.logger.securityEvent("USER_BANNED", { userId });

    return {
      success: true,
      status: 200,
      message: "User banned successfully",
    };
  } catch (error) {
    config.logger.error("Error banning user", { error: String(error) });
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
