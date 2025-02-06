import type { PrismaClient } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import { type LoginOptions, loginUser } from "../auth/login";
import { logoutUser } from "../auth/logout";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

/**
 * Creates a login function with built-in error handling and rate-limiting.
 *
 * - Captures the required dependencies through closure.
 * - Logs unexpected errors and returns a standardized error result.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @param rateLimiter - An optional rate limiter for controlling login attempts.
 * @returns A login function with error handling.
 */
export function loginUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rateLimiter: Ratelimit | null,
) {
  return async (options: LoginOptions) => {
    try {
      return await loginUser(prisma, config, rateLimiter, options);
    } catch (err) {
      config.logger.error("Unexpected error in loginUserFactory", { err });
      return createErrorResult(500, (err as Error).message || "Login error");
    }
  };
}

/**
 * Creates a logout function with built-in error handling.
 *
 * - Captures the required dependencies through closure.
 * - Logs unexpected errors and returns a standardized error result.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A logout function with error handling.
 */
export function logoutUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await logoutUser(prisma, config, rawToken);
    } catch (err) {
      config.logger.error("Unexpected error in logoutUserFactory", { err });
      return createErrorResult(500, (err as Error).message || "Logout error");
    }
  };
}
