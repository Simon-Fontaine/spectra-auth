import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { ErrorCodes } from "../types/errorCodes";
import type { ActionResponse } from "../types/returns";
import { revokeAllSessionsForUserSchema } from "../validations";

export async function revokeAllSessionsForUser(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
  },
  input: {
    userId: string;
  },
): Promise<ActionResponse> {
  const { prisma, config } = context;

  try {
    const validatedInput = revokeAllSessionsForUserSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "revokeAllSessionsForUser",
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { userId } = validatedInput.data;

    await prisma.session.updateMany({
      where: {
        userId: userId,
        isRevoked: false,
      },
      data: { isRevoked: true },
    });
    config.logger.securityEvent("ALL_SESSIONS_REVOKED", { userId });
    return {
      success: true,
      status: 200,
      message: "All sessions revoked for user",
    };
  } catch (err) {
    config.logger.error("Failed to revoke all sessions", {
      userId: input.userId,
      error: err,
    });
    return {
      success: false,
      status: 500,
      message: "Failed to revoke sessions",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
