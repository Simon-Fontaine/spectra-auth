import _ from "lodash";
import { type AegisAuthConfig, configSchema } from "./schema";

export const defaultConfig: AegisAuthConfig = configSchema.parse({});

export function buildConfig(
  userConfig?: Partial<AegisAuthConfig>,
): AegisAuthConfig {
  const merged = _.merge({}, defaultConfig, userConfig);
  const finalConfig = configSchema.parse(merged);

  if (finalConfig.rateLimiting.enabled && !finalConfig.rateLimiting.redis) {
    throw new Error(
      "Rate limiting is enabled but no Redis instance was provided in the config.",
    );
  }

  return finalConfig;
}
