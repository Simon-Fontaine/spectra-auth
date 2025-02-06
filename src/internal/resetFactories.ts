import type { PrismaClient } from "@prisma/client";
import {
  type CompleteResetOptions,
  completePasswordReset,
  initiatePasswordReset,
} from "../auth/reset-password";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

/**
 * Creates a function to initiate the password reset process with error handling.
 *
 * - Sends a password reset email with a verification token.
 * - Captures dependencies such as Prisma and configuration via closure.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A function to initiate password resets with error handling.
 */
export function initiatePasswordResetFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (email: string) => {
    try {
      return await initiatePasswordReset(prisma, config, email);
    } catch (err) {
      config.logger.error("Error in initiatePasswordResetFactory", {
        email,
        error: err,
      });
      return createErrorResult(
        500,
        (err as Error).message || "Password reset initiation failed",
      );
    }
  };
}

/**
 * Creates a function to complete the password reset process with error handling.
 *
 * - Verifies the reset token and updates the user's password.
 * - Captures dependencies such as Prisma and configuration via closure.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A function to complete password resets with error handling.
 */
export function completePasswordResetFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CompleteResetOptions) => {
    try {
      return await completePasswordReset(prisma, config, options);
    } catch (err) {
      config.logger.error("Error in completePasswordResetFactory", {
        token: options.token,
        error: err,
      });
      return createErrorResult(
        500,
        (err as Error).message || "Password reset completion failed",
      );
    }
  };
}
