import type { PrismaClient } from "@prisma/client";
import type { SpectraAuthConfig } from "../config";
import { createVerificationToken } from "../security";
import type {
  ActionResponse,
  PrismaVerification,
  VerificationType,
} from "../types";
import { createTime } from "../utils";

export async function createVerification({
  options,
  prisma,
  config,
}: {
  options: {
    userId: string;
    type: VerificationType;
    tokenExpirySeconds?: number;
  };
  prisma: PrismaClient;
  config: Required<SpectraAuthConfig>;
}): Promise<ActionResponse<{ verification: PrismaVerification }>> {
  const verificationToken = await createVerificationToken({ config });
  const expiresAt = createTime(
    options.tokenExpirySeconds || config.verification.tokenExpirySeconds,
    "s",
  ).getDate();

  const verification = (await prisma.verification.create({
    data: {
      token: verificationToken,
      expiresAt,
      type: options.type,
      userId: options.userId,
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
