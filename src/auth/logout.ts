import type { PrismaClient } from "@prisma/client";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { revokeSession } from "./session";

/**
 * Logs out the user by revoking the session token.
 */
export async function logoutUser(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  rawToken: string,
): Promise<SpectraAuthResult> {
  config.logger.info("Logout attempt", { rawToken });

  return revokeSession(prisma, config, rawToken);
}
