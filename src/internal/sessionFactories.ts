import type { PrismaClient } from "@prisma/client";
import {
  type CreateSessionOptions,
  createSession,
  revokeSession,
  validateSession,
} from "../auth/session";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

/**
 * Creates a factory function for session creation with error handling.
 *
 * - Creates a new session for a user.
 * - Captures Prisma and config dependencies via closure.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A session creation function with error handling.
 */
export function createSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CreateSessionOptions) => {
    try {
      return await createSession(prisma, config, options);
    } catch (err) {
      config.logger.error("Error in createSessionFactory", {
        userId: options.userId,
        error: err,
      });
      return createErrorResult(
        500,
        (err as Error).message || "Failed to create session.",
      );
    }
  };
}

/**
 * Creates a factory function for session validation with error handling.
 *
 * - Validates if the provided session token is valid and not expired.
 * - Captures Prisma and config dependencies via closure.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A session validation function with error handling.
 */
export function validateSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await validateSession(prisma, config, rawToken);
    } catch (err) {
      config.logger.error("Error in validateSessionFactory", {
        tokenPrefix: rawToken.slice(0, 8),
        error: err,
      });
      return createErrorResult(
        500,
        (err as Error).message || "Failed to validate session.",
      );
    }
  };
}

/**
 * Creates a factory function for session revocation with error handling.
 *
 * - Revokes an active session, preventing further use of the session token.
 * - Captures Prisma and config dependencies via closure.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A session revocation function with error handling.
 */
export function revokeSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await revokeSession(prisma, config, rawToken);
    } catch (err) {
      config.logger.error("Error in revokeSessionFactory", {
        tokenPrefix: rawToken.slice(0, 8),
        error: err,
      });
      return createErrorResult(
        500,
        (err as Error).message || "Failed to revoke session.",
      );
    }
  };
}
