import type { PrismaClient } from "@prisma/client";
import { getRandomValues } from "uncrypto";
import type { AuthVerification } from "../interfaces";
import type { SpectraAuthConfig, VerificationType } from "../types";

/** Options for creating a verification token */
export interface CreateVerificationTokenOptions {
  userId: string;
  type: VerificationType;
  expiresIn?: number; // Optional custom expiration time in milliseconds
}

/**
 * Creates a verification token for the specified user and type.
 *
 * - Generates a random 32-byte token.
 * - Stores the token in the database with an expiration date.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - The configuration including logger and security settings.
 * @param options - Options containing user ID, verification type, and expiration time.
 * @returns The generated verification token.
 */
export async function createVerificationToken(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: CreateVerificationTokenOptions,
): Promise<string> {
  // Step 1: Generate a random token
  const buf = new Uint8Array(32);
  getRandomValues(buf);
  const token = bufferToHex(buf);

  const expiresAt = new Date(Date.now() + (options.expiresIn ?? 3600000)); // Default 1-hour expiration

  // Step 2: Store the token in the database
  await prisma.verification.create({
    data: {
      userId: options.userId,
      token,
      type: options.type,
      expiresAt,
    },
  });

  config.logger.info("Created verification token", {
    userId: options.userId,
    type: options.type,
  });

  return token;
}

/** Options for using a verification token */
export interface UseVerificationTokenOptions {
  token: string;
  type: VerificationType;
}

/**
 * Validates and marks a verification token as used.
 *
 * - Checks if the token exists, has not been used, and is not expired.
 * - Marks the token as used if valid.
 *
 * @param prisma - The Prisma client instance for database operations.
 * @param config - The configuration including logger and security settings.
 * @param options - The options containing the token and its type.
 * @returns The updated verification record or null if invalid.
 */
export async function useVerificationToken(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: UseVerificationTokenOptions,
) {
  // Step 1: Find the verification token in the database
  const verif = (await prisma.verification.findUnique({
    where: { token: options.token },
  })) as AuthVerification | null;

  // Step 2: Validate the token
  if (
    !verif ||
    verif.usedAt ||
    verif.type !== options.type ||
    verif.expiresAt < new Date()
  ) {
    config.logger.warn("Invalid or expired verification token", {
      token: options.token,
    });
    return null;
  }

  config.logger.info("Verification token used", {
    token: options.token,
    userId: verif.userId,
  });

  // Step 3: Mark the token as used and return the updated verification record
  return prisma.verification.update({
    where: { id: verif.id },
    data: { usedAt: new Date() },
  });
}

/**
 * Converts a Uint8Array buffer to a hexadecimal string.
 *
 * @param buf - The buffer to convert.
 * @returns The hexadecimal representation of the buffer.
 */
function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}
