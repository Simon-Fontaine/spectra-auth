import type { PrismaClient } from "@prisma/client";
import type { AuthVerification } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { useVerificationToken } from "./verification";

export async function verifyEmail(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  token: string,
): Promise<SpectraAuthResult> {
  try {
    // 1. Use verification token
    const verification = (await useVerificationToken(prisma, config, {
      token,
      type: "EMAIL_VERIFICATION",
    })) as AuthVerification | null;
    if (!verification) {
      return { error: true, status: 400, message: "Invalid or expired token" };
    }

    // 2. Update user email verification status
    await prisma.user.update({
      where: { id: verification.userId },
      data: { isEmailVerified: true },
    });

    config.logger.info("Email verified", { userId: verification.userId });

    return {
      error: false,
      status: 200,
      message: "Email verified.",
    };
  } catch (err) {
    config.logger.error("Failed to verify email", { error: err });
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to verify email",
    };
  }
}
