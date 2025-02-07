import type { PrismaClient } from "@prisma/client";
import {
  type CreateSessionOptions,
  createSession,
  revokeSession,
  validateSession,
} from "../auth/session";
import type { SpectraAuthConfig } from "../types";
import { formatErrorResult } from "../utils/formatResult";

/**
 * Creates a factory function for generating new sessions.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The complete configuration object for Spectra Auth
 * @returns An async function that creates a new session based on the provided options
 * @throws Will return a formatted error result if session creation fails
 *
 * @example
 * ```ts
 * const sessionFactory = createSessionFactory(prisma, config);
 * const session = await sessionFactory({ userId: "123" });
 * ```
 */
export function createSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CreateSessionOptions) => {
    try {
      return await createSession(prisma, config, options);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in createSessionFactory",
        "Failed to create session.",
        500,
      );
    }
  };
}

/**
 * Creates a function to validate session tokens.
 *
 * This factory creates a function that validates session tokens using the provided Prisma client and configuration.
 * The resulting function handles all error cases and formats them according to the configuration.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The complete SpectraAuth configuration object
 * @returns An async function that takes a raw token string and validates the session
 *
 * @throws Will not throw directly, instead returns formatted error results
 *
 * @example
 * ```ts
 * const validateSession = validateSessionFactory(prismaClient, config);
 * const result = await validateSession(token);
 * ```
 */
export function validateSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await validateSession(prisma, config, rawToken);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in validateSessionFactory",
        "Failed to validate session.",
        500,
      );
    }
  };
}

/**
 * Creates a factory function for revoking sessions.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The complete SpectraAuth configuration object
 * @returns An async function that takes a raw token string and revokes the associated session
 *
 * @throws Will return a formatted error result if session revocation fails
 *
 * @example
 * ```ts
 * const revokeSession = revokeSessionFactory(prismaClient, spectraConfig);
 * await revokeSession("user-token-123");
 * ```
 */
export function revokeSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await revokeSession(prisma, config, rawToken);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Error in revokeSessionFactory",
        "Failed to revoke session.",
        500,
      );
    }
  };
}
