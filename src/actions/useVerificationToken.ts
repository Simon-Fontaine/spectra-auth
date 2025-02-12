import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import {
  type ActionResponse,
  ErrorCodes,
  type PrismaVerification,
  type VerificationType,
} from "../types";
import { useVerificationTokenSchema } from "../validations";

export async function useVerificationToken(
  context: {
    prisma: PrismaClient;
    config: AegisAuthConfig;
  },
  input: {
    token: string;
    type: VerificationType;
  },
): Promise<ActionResponse<{ verification: PrismaVerification }>> {
  const { prisma, config } = context;

  try {
    const validatedInput = useVerificationTokenSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "useVerificationToken",
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { token, type } = validatedInput.data;

    const verification = (await prisma.verification.findUnique({
      where: { token: token }, // Use validated token
    })) as PrismaVerification | null;

    if (!verification) {
      config.logger.securityEvent("INVALID_TOKEN", {
        route: type,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid token.",
        code: ErrorCodes.INVALID_TOKEN,
      };
    }

    if (verification.type !== type) {
      // Use validated type
      config.logger.securityEvent("INVALID_TOKEN_TYPE", {
        route: type,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid token type.",
        code: ErrorCodes.INVALID_TOKEN_TYPE,
      };
    }

    if (verification.expiresAt < new Date() || verification.usedAt) {
      config.logger.securityEvent("VERIFICATION_EXPIRED", {
        route: type,
      });
      return {
        success: false,
        status: 400,
        message: "Token expired.",
        code: ErrorCodes.VERIFICATION_EXPIRED,
      };
    }

    await prisma.verification.update({
      where: { id: verification.id },
      data: { usedAt: new Date() },
    });

    return {
      success: true,
      status: 200,
      message: "Token used successfully.",
      data: { verification },
    };
  } catch (error) {
    config.logger.error("Error using verification token", {
      error,
      token: input.token,
      type: input.type,
    });
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred.",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
