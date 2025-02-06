import type { PrismaClient } from "@prisma/client";
import { hashPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { createRouteRateLimiter, limitIPAttempts } from "../utils/rateLimit";
import { sendPasswordResetEmail } from "./email";
import { createVerificationToken, useVerificationToken } from "./verification";

/**
 * Initiates the password reset process for a user.
 *
 * This function creates a password reset token and sends an email to the user
 * with instructions to reset their password.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - The configuration for authentication and logging.
 * @param email - The email address associated with the user account.
 * @returns A result indicating whether the password reset process started successfully.
 */
export async function initiatePasswordReset(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  email: string,
): Promise<SpectraAuthResult> {
  try {
    // Step 1: Check if a user with the given email exists
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

    // Step 2: Create a verification token for password reset
    const token = await createVerificationToken(prisma, config, {
      userId: user.id,
      type: "PASSWORD_RESET",
    });

    // Step 3: Send the password reset email
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

/**
 * Completes the password reset process for a user.
 *
 * This function validates the reset token and updates the user's password,
 * revoking any existing sessions for security.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - The configuration for authentication and logging.
 * @param options - The options containing the reset token and new password.
 * @returns A result indicating the success or failure of the password reset.
 */
export async function completePasswordReset(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: CompleteResetOptions,
): Promise<SpectraAuthResult> {
  try {
    const ip = options.ipAddress;

    // Step 1: Enforce IP-based rate limiting if applicable
    const routeLimiter = createRouteRateLimiter("passwordReset", config);
    if (routeLimiter && ip) {
      const limit = await limitIPAttempts(ip, routeLimiter);
      if (!limit.success) {
        config.logger.warn("IP rate limit exceeded on password-reset init", {
          ip,
        });
        return {
          error: true,
          status: 429,
          message: "Too many attempts. Try again later.",
        };
      }
    }

    // Step 2: Validate and use the verification token
    const verification = await useVerificationToken(prisma, config, {
      token: options.token,
      type: "PASSWORD_RESET",
    });

    if (!verification) {
      return { error: true, status: 400, message: "Invalid or expired token" };
    }

    // Step 3: Hash the new password
    const hashedPassword = await hashPassword(options.newPassword, config);

    // Step 4: Update the user’s password and revoke any active sessions
    await prisma.$transaction([
      prisma.user.update({
        where: { id: verification.userId },
        data: { password: hashedPassword },
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

/** Options required to complete a password reset */
export interface CompleteResetOptions {
  /** The token provided to the user to reset their password. */
  token: string;
  /** The new password the user wishes to set. */
  newPassword: string;
  /** The IP address of the user, used for rate limiting. */
  ipAddress?: string;
}
