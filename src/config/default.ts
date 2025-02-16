import { merge } from "lodash";
import { configSchema } from "./schema";

export function buildConfig(
  userConfig?: Partial<ReturnType<typeof configSchema.parse>>,
) {
  const defaultConfig = configSchema.parse({});
  const merged = merge({}, defaultConfig, userConfig);

  const config = configSchema.parse(merged);

  if (process.env.NODE_ENV === "production") {
    config.security.session.cookie.secure = true;
    config.security.csrf.cookie.secure = true;

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
