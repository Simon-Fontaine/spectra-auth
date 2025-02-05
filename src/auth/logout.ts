import type { PrismaClient } from "@prisma/client";
import type { SpectraAuthResult } from "../types";
import { revokeSession } from "./session";

/**
 * Logs out the user by revoking the session token.
 *
 * @param prisma   - The PrismaClient instance.
 * @param rawToken - The raw (prefix+suffix) session token to revoke.
 * @returns        - A SpectraAuthResult indicating success or error.
 */
export async function logoutUser(
  prisma: PrismaClient,
  rawToken: string,
): Promise<SpectraAuthResult> {
  return revokeSession(prisma, rawToken);
}
