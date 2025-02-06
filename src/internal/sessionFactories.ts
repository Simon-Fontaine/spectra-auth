import type { PrismaClient } from "@prisma/client";
import {
  type CreateSessionOptions,
  createSession,
  revokeSession,
  validateSession,
} from "../auth/session";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

export function createSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: CreateSessionOptions) => {
    try {
      return await createSession(prisma, config, options);
    } catch (err) {
      config.logger.error("Error in createSessionFactory", { err });
      return createErrorResult(
        500,
        (err as Error).message || "CreateSession error",
      );
    }
  };
}

export function validateSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await validateSession(prisma, config, rawToken);
    } catch (err) {
      config.logger.error("Error in validateSessionFactory", { err });
      return createErrorResult(
        500,
        (err as Error).message || "ValidateSession error",
      );
    }
  };
}

export function revokeSessionFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (rawToken: string) => {
    try {
      return await revokeSession(prisma, config, rawToken);
    } catch (err) {
      config.logger.error("Error in revokeSessionFactory", { err });
      return createErrorResult(
        500,
        (err as Error).message || "RevokeSession error",
      );
    }
  };
}
