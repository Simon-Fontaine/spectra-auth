import type { SpectraAuthConfig } from "../types";

export const DEFAULT_CONFIG: SpectraAuthConfig = {
  session: {
    maxAgeSec: 900,
    updateAgeSec: 0,
    maxSessionsPerUser: 5,
  },
  accountLock: {
    threshold: 5,
    durationMs: 15 * 60 * 1000, // 15 minutes
  },
  rateLimit: {
    strategy: "fixedWindow",
    attempts: 5,
    windowSeconds: 600, // 10 minutes
    disable: false,
    kvRestApiUrl: "",
    kvRestApiToken: "",
  },
  csrf: {
    enabled: true,
    secret: process.env.CSRF_SECRET || "CHANGE_ME_IN_PROD",
  },
  passwordPepper: process.env.PASSWORD_PEPPER || "CHANGE_ME_IN_PROD",
  logger: console,
};

export function mergeConfig(
  userConfig: SpectraAuthConfig | undefined,
): Required<SpectraAuthConfig> {
  return {
    ...DEFAULT_CONFIG,
    ...(userConfig || {}),
  };
}
