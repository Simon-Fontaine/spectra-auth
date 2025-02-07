import type { SpectraAuthConfig } from "../types"; // Adjust path if necessary
import { ConsoleLogger } from "../utils/logger";

/**
 * Default configuration for SpectraAuth.
 * These settings are used if no user configuration is provided,
 * or as fallback values when merging configurations.
 */
export const defaultConfig: Required<SpectraAuthConfig> = {
  // Logger configuration
  logger: new ConsoleLogger(), // Default to console logger
  securityEventLogger: new ConsoleLogger(), // Default security event logger also to console

  // Session configuration
  session: {
    cookieName: "spectra.sessionToken", // Base name, suffixes added for CSRF etc.
    maxAgeSec: 30 * 24 * 60 * 60, // 30 days session by default
    tokenLengthBytes: 32, // 256 bits session tokens
    tokenPrefixLengthBytes: 8, // 64 bits prefix for session lookup index
    tokenSecret:
      process.env.SESSION_TOKEN_SECRET || "default-insecure-session-secret", // IMPORTANT: Change in production, use env var!
    csrfSecret: process.env.CSRF_SECRET || "default-insecure-csrf-secret", // IMPORTANT: Change in production, use env var!
    cookieSecure: process.env.NODE_ENV === "production", // Secure cookies in production only
    cookieSameSite: "lax", // Lax is usually a good default for usability and decent CSRF protection
    cookieHttpOnly: true, // Always HttpOnly for session cookies
    maxSessionsPerUser: 5, // Limit concurrent sessions per user to 5 (example)
  },

  // Rate limiting configuration (IP-based)
  rateLimit: {
    disable: false, // Enable rate limiting by default in production
    kvRestApiUrl: process.env.KV_REST_API_URL, // Upstash Redis REST API URL - required for rate limiting
    kvRestApiToken: process.env.KV_REST_API_TOKEN, // Upstash Redis REST API token - required for rate limiting
    loginRoute: {
      enabled: true,
      attempts: 5, // 5 login attempts per window
      windowSeconds: 60 * 5, // 5 minutes window
    },
    registerRoute: {
      enabled: true,
      attempts: 3,
      windowSeconds: 60 * 10, // 10 minutes window for registration
    },
    passwordResetRoute: {
      enabled: true,
      attempts: 3,
      windowSeconds: 60 * 15, // 15 minutes window for password reset initiation
    },
    // You can add more routes here if needed
  },

  // Account lockout configuration
  accountLock: {
    enabled: true, // Account lockout enabled by default
    threshold: 5, // Lockout after 5 failed login attempts
    durationMs: 60 * 60 * 1000, // 1 hour lockout duration
  },

  // Password hashing configuration
  passwordPepper:
    process.env.PASSWORD_PEPPER || "default-insecure-password-pepper", // IMPORTANT: Change in production, use env var!

  // CSRF protection
  csrf: {
    enabled: true, // CSRF protection enabled by default
    cookieName: "spectra.csrfToken", // Name of the CSRF cookie
    headerName: "X-CSRF-Token", // Expected CSRF header name
    formFieldName: "_csrf", // Expected CSRF form field name
    tokenLengthBytes: 32, // Length of CSRF token
    cookieSecure: process.env.NODE_ENV === "production", // Secure CSRF cookie in production
    cookieHttpOnly: true, // CSRF cookie should be HttpOnly
    cookieSameSite: "strict", // Strict SameSite for CSRF cookie
    maxAgeSec: 2 * 60 * 60, // 2 hours CSRF token max age (adjust as needed) - shorter than session
  },
};

/**
 * Merges user-provided configuration with the default configuration.
 * User-provided config takes precedence over defaults.
 *
 * @param userConfig - The configuration object provided by the user (optional).
 * @param defaultConfiguration - The default configuration object.
 * @returns The merged configuration object.
 */
export function mergeConfig<T extends SpectraAuthConfig>(
  userConfig: T | undefined,
  defaultConfiguration: Required<SpectraAuthConfig>,
): Required<SpectraAuthConfig> {
  if (!userConfig) {
    return defaultConfiguration; // If no user config, return defaults
  }

  // Deep merge function - simple recursive merge
  function deepAssign(
    target: Partial<SpectraAuthConfig>,
    source: Partial<SpectraAuthConfig>,
  ) {
    for (const key of Object.keys(source)) {
      const k = key as keyof SpectraAuthConfig;
      if (source[k] instanceof Object && k in target) {
        Object.assign(
          source[k],
          deepAssign(
            target[k] as Partial<SpectraAuthConfig>,
            source[k] as Partial<SpectraAuthConfig>,
          ),
        );
      }
    }
    Object.assign(target || {}, source);
    return target;
  }

  const mergedConfig = { ...defaultConfiguration };
  deepAssign(mergedConfig, userConfig);

  return mergedConfig as Required<SpectraAuthConfig>;
}
