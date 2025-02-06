import type { PrismaClient } from "@prisma/client";
import {
  type CreateVerificationTokenOptions,
  type UseVerificationTokenOptions,
  createVerificationToken,
  useVerificationToken,
} from "../auth/verification";
import { verifyEmail } from "../auth/verify-email";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

export function createVerificationTokenFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CreateVerificationTokenOptions) => {
    try {
      return await createVerificationToken(prisma, config, options);
    } catch (err) {
      config.logger.error("Error in createVerificationTokenFactory", { err });
      return "";
    }
  };
}

export function useVerificationTokenFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: UseVerificationTokenOptions) => {
    try {
      return await useVerificationToken(prisma, config, options);
    } catch (err) {
      config.logger.error("Error in useVerificationTokenFactory", { err });
      return null;
    }
  };
}

export function verifyEmailFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (token: string) => {
    try {
      return await verifyEmail(prisma, config, token);
    } catch (err) {
      config.logger.error("Error in verifyEmailFactory", { err });
      return createErrorResult(
        500,
        (err as Error).message || "VerifyEmail error",
      );
    }
  };
}
