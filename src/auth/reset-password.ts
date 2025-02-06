import type { PrismaClient } from "@prisma/client";
import { hashPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { sendPasswordResetEmail } from "./email";
import { createVerificationToken, useVerificationToken } from "./verification";

/**
 * Initiates a password reset (optionally logs or reads from config).
 */
export async function initiatePasswordReset(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  email: string,
): Promise<SpectraAuthResult> {
  try {
    // 1. Find user by email
    const user = (await prisma.user.findUnique({
      where: { email },
    })) as AuthUser | null;

    if (!user) {
      return {
        error: false,
        status: 200,
        message: "If that email exists, a reset link was sent.",
      };
    }

    // 2. Create verification token
    const token = await createVerificationToken(prisma, config, {
      userId: user.id,
      type: "PASSWORD_RESET",
    });

    // 3. Send email
    await sendPasswordResetEmail(email, token);

    config.logger.info("Password reset initiated", { userId: user.id });

    return {
      error: false,
      status: 200,
      message: "Reset initiated. Check your email.",
    };
  } catch (err) {
    config.logger.error("Failed to initiate password reset", { error: err });
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to initiate password reset",
    };
  }
}

export interface CompleteResetOptions {
  token: string;
  newPassword: string;
}

/**
 * Completes the password reset using a token + new password.
 */
export async function completePasswordReset(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: CompleteResetOptions,
): Promise<SpectraAuthResult> {
  try {
    const verification = await useVerificationToken(prisma, config, {
      token: options.token,
      type: "PASSWORD_RESET",
    });
    if (!verification) {
      return { error: true, status: 400, message: "Invalid or expired token" };
    }

    const hashed = await hashPassword(options.newPassword, config);

    await prisma.$transaction([
      prisma.user.update({
        where: { id: verification.userId },
        data: { password: hashed },
      }),
      prisma.session.updateMany({
        where: { userId: verification.userId },
        data: { isRevoked: true },
      }),
    ]);

    config.logger.info("Password reset successful", {
      userId: verification.userId,
    });

    return {
      error: false,
      status: 200,
      message: "Password reset successful.",
    };
  } catch (err) {
    config.logger.error("Failed to complete password reset", { error: err });
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to complete password reset",
    };
  }
}
