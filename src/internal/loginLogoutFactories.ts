import type { PrismaClient } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import { type LoginOptions, loginUser } from "../auth/login";
import { logoutUser } from "../auth/logout";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

/**
 * Wraps loginUser with a closure capturing config + rateLimiter.
 */
export function loginUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rateLimiter: Ratelimit,
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
 * Wraps logoutUser with a closure capturing config.
 */
export function logoutUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await logoutUser(prisma, rawToken);
    } catch (err) {
      config.logger.error("Unexpected error in logoutUserFactory", { err });
      return createErrorResult(500, (err as Error).message || "Logout error");
    }
  };
}
