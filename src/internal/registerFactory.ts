import type { PrismaClient } from "@prisma/client";
import { type RegisterOptions, registerUser } from "../auth/register";
import type { SpectraAuthConfig } from "../types";
import { createErrorResult } from "../utils/logger";

export function registerUserFactory(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
) {
  return async (options: RegisterOptions) => {
    try {
      return await registerUser(prisma, config, options);
    } catch (err) {
      config.logger.error("Unexpected error in registerUserFactory", { err });
      return createErrorResult(
        500,
        (err as Error).message || "Registration error",
      );
    }
  };
}
