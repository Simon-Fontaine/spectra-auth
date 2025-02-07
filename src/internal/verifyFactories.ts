import type { PrismaClient } from "@prisma/client";
import {
  type CreateVerificationTokenOptions,
  type UseVerificationTokenOptions,
  createVerificationToken,
  useVerificationToken,
} from "../auth/verification";
import { verifyEmail } from "../auth/verify-email";
import type { SpectraAuthConfig } from "../types";
import { formatErrorResult } from "../utils/formatResult";

/**
 * Creates a factory function for generating verification tokens.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The complete Spectra Auth configuration object
 * @returns An async function that creates verification tokens
 *
 * @throws Will return a formatted error result if token creation fails
 *
 * @example
 * ```typescript
 * const verifyTokenFactory = createVerificationTokenFactory(prismaClient, authConfig);
 * const token = await verifyTokenFactory({ email: "user@example.com" });
 * ```
 */
export function createVerificationTokenFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CreateVerificationTokenOptions): Promise<string> => {
    try {
      return await createVerificationToken(prisma, config, options);
    } catch (err) {
      formatErrorResult(
        config,
        err,
        "Error in createVerificationTokenFactory",
        "Failed to create verification token",
        500,
      );
      return "";
    }
  };
}

/**
 * Creates a factory function for handling verification tokens.
 *
 * @param prisma - The Prisma client instance for database operations
 * @param config - The required Spectra Auth configuration object
 * @returns An async function that processes verification token operations
 *
 * The returned function:
 * - Takes verification token options as parameter
 * - Attempts to process the verification token
 * - Handles errors by formatting them according to config
 * - Returns null if operation fails
 *
 * @throws Formats and handles any errors that occur during token verification
 */
export function useVerificationTokenFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: UseVerificationTokenOptions) => {
    try {
      return await useVerificationToken(prisma, config, options);
    } catch (err) {
      formatErrorResult(
        config,
        err,
        "Error in useVerificationTokenFactory",
        "Failed to use verification token",
        500,
      );
      return null;
    }
  };
}

/**
 * Creates a function that verifies an email using a token.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The complete SpectraAuth configuration object
 * @returns An async function that takes a token string and attempts to verify an email
 *
 * @throws Will return a formatted error result if verification fails
 *
 * @example
 * ```ts
 * const verifyEmail = verifyEmailFactory(prismaClient, config);
 * const result = await verifyEmail("verification-token");
 * ```
 */
export function verifyEmailFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (token: string) => {
    try {
      return await verifyEmail(prisma, config, token);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in verifyEmailFactory",
        "VerifyEmail error",
        500,
      );
    }
  };
}
