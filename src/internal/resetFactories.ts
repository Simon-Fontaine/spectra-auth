import type { PrismaClient } from "@prisma/client";
import {
  type CompleteResetOptions,
  completePasswordReset,
  initiatePasswordReset,
} from "../auth/reset-password";
import type { SpectraAuthConfig } from "../types";
import { formatErrorResult } from "../utils/formatResult";

/**
 * Creates a factory function for initiating password reset processes.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The complete Spectra Auth configuration object
 * @returns An async function that takes an email address and initiates a password reset process
 *
 * @throws Will return a formatted error result if password reset initiation fails
 *
 * @example
 * const resetPasswordFn = initiatePasswordResetFactory(prismaClient, authConfig);
 * await resetPasswordFn('user@example.com');
 */
export function initiatePasswordResetFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (email: string) => {
    try {
      return await initiatePasswordReset(prisma, config, email);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in initiatePasswordResetFactory",
        "Password reset initiation failed",
        500,
      );
    }
  };
}

/**
 * Creates a factory function for completing password reset operations.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The complete Spectra Auth configuration object
 * @returns An async function that handles password reset completion
 *
 * @throws Will return a formatted error result if password reset completion fails
 *
 * @example
 * const completeReset = completePasswordResetFactory(prisma, config);
 * const result = await completeReset({ token: "reset123", newPassword: "password123" });
 */
export function completePasswordResetFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CompleteResetOptions) => {
    try {
      return await completePasswordReset(prisma, config, options);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in completePasswordResetFactory",
        "Password reset completion failed",
        500,
      );
    }
  };
}
