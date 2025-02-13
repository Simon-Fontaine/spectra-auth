import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { type ActionResponse, ErrorCodes, type PrismaUser } from "../types";
import { updateUserRolesSchema } from "../validations";

export async function updateUserRoles(
  context: {
    prisma: PrismaClient;
    config: AegisAuthConfig;
  },
  input: {
    userId: string;
    roles: string[];
  },
): Promise<ActionResponse> {
  const { prisma, config } = context;

  try {
    const validatedInput = updateUserRolesSchema.safeParse(input);
    config.logger.securityEvent("INVALID_INPUT", { route: "updateUserRoles" });
    if (!validatedInput.success) {
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { userId, roles } = validatedInput.data;

    const user = (await prisma.user.findUnique({
      where: { id: userId },
    })) as PrismaUser | null;
    if (!user) {
      config.logger.securityEvent("USER_NOT_FOUND", {
        route: "updateUserRoles",
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
        roles,
      },
    });

    config.logger.securityEvent("USER_ROLES_UPDATED", {
      userId,
      roles,
    });

    return {
      success: true,
      status: 200,
      message: "Roles updated successfully",
    };
  } catch (error) {
    config.logger.error("Error updating user roles", { error: String(error) });
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
