import type { PrismaClient } from "@prisma/client";
import { type LoginOptions, loginUser } from "../auth/login";
import { logoutUser } from "../auth/logout";
import type { SpectraAuthConfig } from "../types";
import { formatErrorResult } from "../utils/formatResult";

/**
 * Creates a factory function for user login operations.
 *
 * @param prisma - The Prisma client instance used for database operations
 * @param config - The required configuration object for Spectra Auth
 * @returns An async function that handles user login with error handling
 *
 * @example
 * ```ts
 * const login = loginUserFactory(prismaClient, spectraConfig);
 * const result = await login({ email: "user@example.com", password: "pass123" });
 * ```
 *
 * @throws Will format and return error results according to config if login fails
 */
export function loginUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: LoginOptions) => {
    try {
      return await loginUser(prisma, config, options);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Unexpected error in loginUserFactory",
        "Login error",
        500,
      );
    }
  };
}

/**
 * Creates a function to handle user logout operations with error handling.
 *
 * @param prisma - The Prisma client instance for database operations
 * @param config - The complete configuration object for Spectra Auth
 * @returns An async function that accepts a raw token string and processes the logout
 *
 * The returned function:
 * - Takes a raw token string as input
 * - Attempts to log out the user
 * - Returns a formatted error if the operation fails
 * - Returns the logout result if successful
 *
 * @throws Will return a formatted error object if any exception occurs during logout
 */
export function logoutUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await logoutUser(prisma, config, rawToken);
    } catch (err) {
      return formatErrorResult(
        config,
        err,
        "Unexpected error in logoutUserFactory",
        "Logout error",
        500,
      );
    }
  };
}
