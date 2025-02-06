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
  const { logger } = config;
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

  logger.info("Created verification token", {
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
  const { logger } = config;
  const verif = (await prisma.verification.findUnique({
    where: { token: options.token },
  })) as AuthVerification | null;
  if (
    !verif ||
    verif.usedAt ||
    verif.type !== options.type ||
    verif.expiresAt < new Date()
  ) {
    logger.warn("Invalid or expired verification token", {
      token: options.token,
    });
    return null;
  }

  logger.info("Verification token used", {
    token: options.token,
    userId: verif.userId,
  });

  return prisma.verification.update({
    where: { id: verif.id },
    data: { usedAt: new Date() },
  });
}

function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}
