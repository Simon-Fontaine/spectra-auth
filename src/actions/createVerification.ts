import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { createVerificationToken } from "../security";
import type {
  ActionResponse,
  PrismaVerification,
  VerificationType,
} from "../types";
import { createTime } from "../utils";

export async function createVerification(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
  },
  input: {
    userId: string;
    type: VerificationType;
    tokenExpirySeconds?: number;
  },
): Promise<ActionResponse<{ verification: PrismaVerification }>> {
  const { prisma, config } = context;

  const verificationToken = await createVerificationToken({ config });
  const expiresAt = createTime(
    input.tokenExpirySeconds || config.verification.tokenExpirySeconds,
    "s",
  ).getDate();

  const verification = (await prisma.verification.create({
    data: {
      token: verificationToken,
      expiresAt,
      type: input.type,
      userId: input.userId,
    },
  })) as PrismaVerification;

  config.logger.securityEvent("VERIFICATION_CREATED", {
    verificationId: verification.id,
    userId: verification.userId,
    type: verification.type,
  });

  return {
    success: true,
    status: 200,
    message: "Verification created",
    data: { verification },
  };
}
