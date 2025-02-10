import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import {
  type ActionResponse,
  ErrorCodes,
  type PrismaVerification,
  type VerificationType,
} from "../types";

export async function useVerificationToken(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
  },
  input: {
    token: string;
    type: VerificationType;
  },
): Promise<ActionResponse<{ verification: PrismaVerification }>> {
  const { prisma, config } = context;

  const verification = (await prisma.verification.findUnique({
    where: { token: input.token },
  })) as PrismaVerification | null;

  if (!verification) {
    config.logger.securityEvent("INVALID_TOKEN", {
      route: input.type,
    });
    return {
      success: false,
      status: 400,
      message: "Invalid token.",
      code: ErrorCodes.INVALID_TOKEN,
    };
  }

  if (verification.type !== input.type) {
    config.logger.securityEvent("INVALID_TOKEN_TYPE", {
      route: input.type,
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
      route: input.type,
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
}
