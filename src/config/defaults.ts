import type { SpectraAuthConfig } from "../types";

export const DEFAULT_CONFIG: SpectraAuthConfig = {
  session: {
    maxAgeSec: 30 * 24 * 60 * 60, // 30 days
    updateAgeSec: 24 * 60 * 60, // 1 day
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
    secret: "CHANGE_ME_IN_PROD",
  },
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
