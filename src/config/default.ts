import lodash from "lodash";
import type { AegisAuthConfig } from "../types";
import { configSchema } from "./schema";

export const defaultConfig = configSchema.parse({});

export function buildConfig(userConfig?: Partial<AegisAuthConfig>) {
  const merged = lodash.merge({}, defaultConfig, userConfig);
  const config = configSchema.parse(merged);

  if (
    config.protection.rateLimit.enabled &&
    !config.protection.rateLimit.redis
  ) {
    throw new Error(
      "Rate limiting is enabled but no Redis configuration provided",
    );
  }

  return config;
}
