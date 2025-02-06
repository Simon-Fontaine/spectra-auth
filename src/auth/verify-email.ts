import type { PrismaClient } from "@prisma/client";
import type { AuthVerification } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { useVerificationToken } from "./verification";

/**
 * Verifies a user's email using a token.
 *
 * - Validates the email verification token.
 * - Updates the user's email verification status if successful.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - The configuration for authentication and logging.
 * @param token - The token to verify the user's email.
 * @returns A result indicating the success or failure of the email verification.
 */
export async function verifyEmail(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  token: string,
): Promise<SpectraAuthResult> {
  try {
    // Step 1: Use verification token
    const verification = (await useVerificationToken(prisma, config, {
      token,
      type: "EMAIL_VERIFICATION",
    })) as AuthVerification | null;

    if (!verification) {
      return { error: true, status: 400, message: "Invalid or expired token" };
    }

    // Step 2: Update the user's email verification status
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
