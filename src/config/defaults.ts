import type { SpectraAuthConfig } from "../types";

export const DEFAULT_CONFIG: SpectraAuthConfig = {
  session: {
    maxAgeSec: 900, // 15 minutes
    updateAgeSec: 0, // No sliding renewal
    maxSessionsPerUser: 5, // Enforce concurrency limit
  },
  accountLock: {
    threshold: 5,
    durationMs: 15 * 60 * 1000, // 15 minutes
  },
  rateLimit: {
    strategy: "fixedWindow",
    attempts: 5,
    windowSeconds: 600,
    disable: false,
    kvRestApiUrl: "",
    kvRestApiToken: "",
  },
  csrf: {
    enabled: true,
    // Fallback, but each session has its own CSRF secret
    secret: process.env.CSRF_SECRET || "CHANGE_ME_IN_PROD",
  },
  // For Argon2 password hashing
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
