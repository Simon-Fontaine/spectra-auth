import type { PrismaClient } from "@prisma/client";
import { type RegisterOptions, registerUser } from "../auth/register";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

/**
 * Creates a registration function with built-in error handling.
 *
 * - Captures the necessary dependencies through closure.
 * - Handles unexpected errors and logs them for diagnostics.
 *
 * @param prisma - The Prisma client instance for database access.
 * @param config - The authentication configuration.
 * @returns A registration function with error handling.
 */
export function registerUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: RegisterOptions) => {
    try {
      return await registerUser(prisma, config, options);
    } catch (err) {
      config.logger.error("Unexpected error in registerUserFactory", { err });

      return createErrorResult(
        500,
        (err as Error).message || "Registration error",
      );
    }
  };
}
