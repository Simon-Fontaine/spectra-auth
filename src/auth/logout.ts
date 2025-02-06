import type { PrismaClient } from "@prisma/client";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { revokeSession } from "./session";

/**
 * Logs out the user by revoking the active session token.
 *
 * This ensures that the session is invalidated and cannot be used for future requests.
 * Proper logging is done to track the logout event.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - Authentication configuration including logging utilities.
 * @param rawToken - The raw session token to be revoked.
 * @returns A result indicating the success or failure of the logout operation.
 */
export async function logoutUser(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  try {
    config.logger.info("Logout attempt initiated", {
      tokenPrefix: `${rawToken.slice(0, 8)}...`,
    });

    // Revoke the session and log the outcome
    const result = await revokeSession(prisma, config, rawToken);

    if (!result.error) {
      config.logger.info("Logout successful", {
        tokenPrefix: `${rawToken.slice(0, 8)}...`,
      });
    } else {
      config.logger.warn("Logout failed", {
        tokenPrefix: `${rawToken.slice(0, 8)}...`,
        reason: result.message,
      });
    }

    return result;
  } catch (err) {
    config.logger.error("Unexpected error during logout", {
      error: err,
      tokenPrefix: `${rawToken.slice(0, 8)}...`,
    });
    return {
      error: true,
      status: 500,
      message: "Logout failed due to an unexpected error.",
    };
  }
}
