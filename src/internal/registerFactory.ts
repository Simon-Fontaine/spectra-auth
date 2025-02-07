import type { PrismaClient } from "@prisma/client";
import { type RegisterOptions, registerUser } from "../auth/register";
import type { SpectraAuthConfig } from "../types";
import { formatErrorResult } from "../utils/formatResult";

/**
 * Creates a factory function for registering users with error handling
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The required configuration for Spectra Auth
 * @returns An async function that takes RegisterOptions and handles user registration
 *
 * @throws Will return a formatted error result if registration fails
 *
 * @example
 * const register = registerUserFactory(prisma, config);
 * const result = await register({ email: "user@example.com", password: "pass123" });
 */
export function registerUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: RegisterOptions) => {
    try {
      return await registerUser(prisma, config, options);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Unexpected error in registerUserFactory",
        "Registration error",
        500,
      );
    }
  };
}
