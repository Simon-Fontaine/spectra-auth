import type { PrismaClient } from "@prisma/client";
import {
  type CompleteResetOptions,
  completePasswordReset,
  initiatePasswordReset,
} from "../auth/reset-password";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

export function initiatePasswordResetFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (email: string) => {
    try {
      return await initiatePasswordReset(prisma, config, email);
    } catch (err) {
      config.logger.error("Error in initiatePasswordResetFactory", { err });
      return createErrorResult(
        500,
        (err as Error).message || "initiateReset error",
      );
    }
  };
}

export function completePasswordResetFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CompleteResetOptions) => {
    try {
      return await completePasswordReset(prisma, config, options);
    } catch (err) {
      config.logger.error("Error in completePasswordResetFactory", { err });
      return createErrorResult(
        500,
        (err as Error).message || "completeReset error",
      );
    }
  };
}
