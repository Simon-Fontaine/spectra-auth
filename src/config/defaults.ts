import type { SpectraAuthConfig } from "../types";

/**
 * Default configuration settings for the SpectraAuth authentication system.
 *
 * - Defines session timeouts, rate limits, and security measures.
 * - These settings can be overridden by user-provided configurations.
 */
export const DEFAULT_CONFIG: SpectraAuthConfig = {
  session: {
    maxAgeSec: 900, // 15 minutes session expiration
    updateAgeSec: 0, // No sliding session renewal
    maxSessionsPerUser: 5, // Limit active sessions per user
  },
  accountLock: {
    threshold: 5, // Lock after 5 failed login attempts
    durationMs: 15 * 60 * 1000, // 15-minute lock duration
  },
  rateLimit: {
    strategy: "fixedWindow", // Fixed window rate limiting strategy
    attempts: 5, // 5 attempts allowed per window
    windowSeconds: 600, // 10-minute rate-limiting window
    disable: false, // Rate limiting enabled
    kvRestApiUrl: "", // Placeholder for Upstash REST API URL
    kvRestApiToken: "", // Placeholder for Upstash API token
  },
  routeRateLimit: {
    login: {
      attempts: 10, // 10 login attempts per 5 minutes
      windowSeconds: 300, // 5-minute window for login
    },
    register: {
      attempts: 5, // 5 registration attempts per 15 minutes
      windowSeconds: 900, // 15-minute window for registration
    },
    passwordReset: {
      attempts: 3, // 3 reset attempts per 20 minutes
      windowSeconds: 1200, // 20-minute window for password reset
    },
  },
  csrf: {
    enabled: true, // Enable CSRF protection
    secret: process.env.CSRF_SECRET || "CHANGE_ME_IN_PROD", // Default or env-provided CSRF secret
  },
  passwordPepper: process.env.PASSWORD_PEPPER || "CHANGE_ME_IN_PROD", // Default or env-provided password pepper for Argon2
  logger: console, // Default logger using the console
};

/**
 * Merges user-provided configuration with the default configuration.
 *
 * - User settings override the default values if provided.
 * - Ensures required properties are always set.
 *
 * @param userConfig - The user-defined configuration settings.
 * @returns A complete and merged configuration object.
 */
export function mergeConfig(
  userConfig: SpectraAuthConfig | undefined,
): Required<SpectraAuthConfig> {
  return {
    ...DEFAULT_CONFIG,
    ...(userConfig || {}),
  };
}
