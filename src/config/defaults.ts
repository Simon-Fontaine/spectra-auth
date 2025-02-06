import type { SpectraAuthConfig } from "../types";

export const DEFAULT_CONFIG: Required<SpectraAuthConfig> = {
  // Sessions
  sessionMaxAgeSec: 30 * 24 * 60 * 60, // 30 days
  sessionUpdateAgeSec: 24 * 60 * 60, // 1 day

  // Lockouts
  accountLockThreshold: 5,
  accountLockDurationMs: 15 * 60 * 1000, // 15 minutes

  // Rate-limiting
  rateLimitingStrategy: "fixedWindow",
  attempts: 10,
  windowSeconds: 900, // 15 minutes
  disableRateLimit: false,

  // Upstash credentials
  kvRestApiUrl: "",
  kvRestApiToken: "",

  // CSRF
  enableCSRF: false,
  csrfSecret: "CHANGE_ME_IN_PROD",

  // Logger
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
