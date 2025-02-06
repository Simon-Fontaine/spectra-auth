import type { PrismaClient } from "@prisma/client";
import { getRandomValues } from "uncrypto";
import type { AuthVerification } from "../interfaces";
import type { SpectraAuthConfig, VerificationType } from "../types";

export interface CreateVerificationTokenOptions {
  userId: string;
  type: VerificationType;
  expiresIn?: number;
}

export async function createVerificationToken(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: CreateVerificationTokenOptions,
): Promise<string> {
  // 1. Generate random token
  const buf = new Uint8Array(32);
  getRandomValues(buf);
  const token = bufferToHex(buf);

  const expiresAt = new Date(Date.now() + (options.expiresIn ?? 3600000));

  // 2. Create verification token
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

export interface UseVerificationTokenOptions {
  token: string;
  type: VerificationType;
}

export async function useVerificationToken(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: UseVerificationTokenOptions,
) {
  // 1. Find verification token
  const verif = (await prisma.verification.findUnique({
    where: { token: options.token },
  })) as AuthVerification | null;

  // 2. Verify token
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

  // 3. Mark token as used
  return prisma.verification.update({
    where: { id: verif.id },
    data: { usedAt: new Date() },
  });
}

function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}
