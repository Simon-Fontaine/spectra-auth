import type { PrismaClient } from "@prisma/client";
import {
  type CreateVerificationTokenOptions,
  type UseVerificationTokenOptions,
  createVerificationToken,
  useVerificationToken,
} from "../auth/verification";
import { verifyEmail } from "../auth/verify-email";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

/**
 * Creates a factory function to generate verification tokens with error handling.
 *
 * - Generates a verification token and stores it in the database.
 * - Captures dependencies such as Prisma and configuration via closure.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A function to generate verification tokens with error handling.
 */
export function createVerificationTokenFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CreateVerificationTokenOptions): Promise<string> => {
    try {
      return await createVerificationToken(prisma, config, options);
    } catch (err) {
      config.logger.error("Error in createVerificationTokenFactory", {
        userId: options.userId,
        type: options.type,
        error: err,
      });
      return "";
    }
  };
}

/**
 * Creates a factory function to use verification tokens with error handling.
 *
 * - Verifies and marks the token as used if valid.
 * - Captures dependencies such as Prisma and configuration via closure.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A function to verify and use tokens with error handling.
 */
export function useVerificationTokenFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: UseVerificationTokenOptions) => {
    try {
      return await useVerificationToken(prisma, config, options);
    } catch (err) {
      config.logger.error("Error in useVerificationTokenFactory", {
        token: options.token,
        type: options.type,
        error: err,
      });
      return null;
    }
  };
}

/**
 * Creates a factory function to verify email addresses with error handling.
 *
 * - Verifies the email associated with the provided verification token.
 * - Captures dependencies such as Prisma and configuration via closure.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A function to verify email addresses with error handling.
 */
export function verifyEmailFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (token: string) => {
    try {
      return await verifyEmail(prisma, config, token);
    } catch (err) {
      config.logger.error("Error in verifyEmailFactory", { token, error: err });
      return createErrorResult(
        500,
        (err as Error).message || "VerifyEmail error",
      );
    }
  };
}
