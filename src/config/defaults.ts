import type { RateLimitingStrategy } from "../types";

export interface LoggerInterface {
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
}

export interface SpectraAuthConfig {
  // Session
  sessionMaxAgeSec?: number;
  sessionUpdateAgeSec?: number;

  // Account Lockouts
  accountLockThreshold?: number;
  accountLockDurationMs?: number;

  // Rate-limiting
  rateLimitingStrategy?: RateLimitingStrategy;
  attempts?: number;
  windowSeconds?: number;

  // CSRF
  enableCSRF?: boolean;
  csrfSecret?: string; // used to generate & verify CSRF tokens

  // Logging
  logger?: LoggerInterface;
}

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
