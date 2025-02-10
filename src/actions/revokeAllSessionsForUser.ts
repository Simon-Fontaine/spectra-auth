import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { ErrorCodes } from "../types/errorCodes";
import type { ActionResponse } from "../types/returns";

export async function revokeAllSessionsForUser(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
  },
  input: {
    userId: string;
  },
): Promise<ActionResponse> {
  try {
    const { prisma, config } = context;
    const { userId } = input;

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
    const { config } = context;
    const { userId } = input;

    config.logger.error("Failed to revoke all sessions", {
      userId,
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
