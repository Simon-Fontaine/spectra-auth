import type { PrismaClient } from "@prisma/client";
import { hashPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthResult } from "../types";
import { sendPasswordResetEmail } from "./email";
import { createVerificationToken, useVerificationToken } from "./verification";

/**
 * Initiates a password reset for the specified email address.
 * Sends an email with a unique token.
 *
 * @param prisma - The PrismaClient instance.
 * @param email  - The user’s email address to reset password for.
 * @returns      - A SpectraAuthResult indicating success or error.
 */
export async function initiatePasswordReset(
  prisma: PrismaClient,
  email: string,
): Promise<SpectraAuthResult> {
  try {
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

    const token = await createVerificationToken(prisma, {
      userId: user.id,
      type: "PASSWORD_RESET",
    });
    await sendPasswordResetEmail(email, token);

    return {
      error: false,
      status: 200,
      message: "Reset initiated. Check your email.",
    };
  } catch (err) {
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to initiate password reset",
    };
  }
}

export interface CompleteResetOptions {
  /** The token from the password reset email. */
  token: string;
  /** The new plaintext password. */
  newPassword: string;
}

/**
 * Completes the password reset using a token + new password.
 *
 * @param prisma  - The PrismaClient instance.
 * @param options - { token, newPassword }
 * @returns       - A SpectraAuthResult with success or error details.
 */
export async function completePasswordReset(
  prisma: PrismaClient,
  options: CompleteResetOptions,
): Promise<SpectraAuthResult> {
  try {
    const verification = await useVerificationToken(prisma, {
      token: options.token,
      type: "PASSWORD_RESET",
    });
    if (!verification) {
      return { error: true, status: 400, message: "Invalid or expired token" };
    }

    // Hash the new password
    const hashed = await hashPassword(options.newPassword);

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

    return {
      error: false,
      status: 200,
      message: "Password reset successful.",
    };
  } catch (err) {
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Failed to complete password reset",
    };
  }
}
