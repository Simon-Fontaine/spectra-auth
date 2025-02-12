import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { type ActionResponse, ErrorCodes } from "../types";
import { logoutUserSchema } from "../validations";
import { revokeSession } from "./revokeSession";

export async function logoutUser(
  context: {
    prisma: PrismaClient;
    config: AegisAuthConfig;
  },
  input: {
    sessionToken: string;
  },
): Promise<ActionResponse> {
  const { config } = context;

  try {
    const validatedInput = logoutUserSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "logoutUser",
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { sessionToken } = validatedInput.data;

    const result = await revokeSession(context, { sessionToken });

    if (!result.success) {
      return result;
    }

    return {
      success: true,
      status: 200,
      message: "User logged out",
    };
  } catch (error) {
    config.logger.error("Error during logout", {
      error,
      sessionToken: input.sessionToken,
    });
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred.",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
