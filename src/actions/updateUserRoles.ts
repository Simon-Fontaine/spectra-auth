import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { type ActionResponse, ErrorCodes } from "../types";
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
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "updateUserRoles",
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { userId, roles } = validatedInput.data;

    const user = await prisma.user.findUnique({
      where: { id: userId },
    });
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

    await prisma.$transaction(async (tx) => {
      await tx.userRoles.deleteMany({
        where: { userId },
      });

      for (const roleName of roles) {
        const role = await tx.role.upsert({
          where: { name: roleName },
          update: {},
          create: {
            name: roleName,
            permissions: [],
          },
        });

        await tx.userRoles.create({
          data: {
            userId,
            roleId: role.id,
          },
        });
      }
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
