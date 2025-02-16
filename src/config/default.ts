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

  if (process.env.NODE_ENV === "production") {
    config.security.session.cookie.secure = true;
    config.security.csrf.cookie.secure = true;

    config.security.session.cookie.secure = true;

    if (config.security.session.secret === "change-me") {
      throw new Error(
        "Please set a secure SESSION_TOKEN_SECRET in production.",
      );
    }
    if (config.security.csrf.secret === "change-me") {
      throw new Error("Please set a secure CSRF_TOKEN_SECRET in production.");
    }
  }

  return config;
}
