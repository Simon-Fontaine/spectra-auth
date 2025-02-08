import type { PrismaClient } from "@prisma/client";
import type { SpectraAuthConfig } from "../config";
import {
  type ActionResponse,
  ErrorCodes,
  type PrismaVerification,
  type VerificationType,
} from "../types";

export async function useVerificationToken({
  options,
  prisma,
  config,
}: {
  options: {
    input: {
      token: string;
      type: VerificationType;
    };
  };
  prisma: PrismaClient;
  config: Required<SpectraAuthConfig>;
}): Promise<ActionResponse<{ verification: PrismaVerification }>> {
  const { input } = options;

  const verification = (await prisma.verification.update({
    where: { token: input.token, type: input.type },
    data: { usedAt: new Date() },
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

  return {
    success: true,
    status: 200,
    message: "Token used successfully.",
    data: { verification },
  };
}
