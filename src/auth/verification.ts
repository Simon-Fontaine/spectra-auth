import type { PrismaClient } from "@prisma/client";
import { getRandomValues } from "uncrypto";
import type { AuthVerification } from "../interfaces";

export type VerificationType =
  | "EMAIL_VERIFICATION"
  | "PASSWORD_RESET"
  | "ACCOUNT_DELETION"
  | "EMAIL_CHANGE";

export interface CreateVerificationTokenOptions {
  /** The user ID. */
  userId: string;
  /** The type of verification. */
  type: VerificationType;
  /** Optional expiration (in ms). Defaults to 1 hour if omitted. */
  expiresIn?: number;
}

/**
 * Creates a new verification token for the specified user.
 * The token is stored in the DB and returned.
 */
export async function createVerificationToken(
  prisma: PrismaClient,
  options: CreateVerificationTokenOptions,
): Promise<string> {
  const buf = new Uint8Array(32);
  getRandomValues(buf);
  const token = bufferToHex(buf);

  const expiresAt = new Date(Date.now() + (options.expiresIn ?? 3600000));

  await prisma.verification.create({
    data: {
      userId: options.userId,
      token,
      type: options.type,
      expiresAt,
    },
  });

  return token;
}

export interface UseVerificationTokenOptions {
  /** The raw token from the user. */
  token: string;
  /** The verification type expected. */
  type: VerificationType;
}

/**
 * Marks the verification token as used, if valid.
 *
 * @returns The updated verification record or null if invalid/expired.
 */
export async function useVerificationToken(
  prisma: PrismaClient,
  options: UseVerificationTokenOptions,
) {
  const verif = (await prisma.verification.findUnique({
    where: { token: options.token },
  })) as AuthVerification | null;
  if (
    !verif ||
    verif.usedAt ||
    verif.type !== options.type ||
    verif.expiresAt < new Date()
  ) {
    return null;
  }

  return prisma.verification.update({
    where: { id: verif.id },
    data: { usedAt: new Date() },
  });
}

/** Helper to convert buffer to hex. */
function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}
