import { getRandomValues } from "uncrypto";
import { base64Url } from "../crypto";
import type { SpectraAuthConfig } from "../types"; // Adjust path
import { consoleLogger } from "../utils/logger"; // Assuming you have a basic console logger utility

export const defaultConfig: SpectraAuthConfig = {
  session: {
    maxAgeSec: 30 * 24 * 3600,
    updateAgeSec: 24 * 3600,
    maxSessionsPerUser: 5,
    cookieSecure: process.env.NODE_ENV === "production", // Secure by default in production
    cookieSameSite: "lax", // Lax by default
  },
  accountLock: {
    threshold: 5,
    durationMs: 15 * 60 * 1000, // 15 minutes
  },
  rateLimit: {
    disable: false, // Rate limiting enabled by default
    kvRestApiUrl: process.env.KV_REST_API_URL,
    kvRestApiToken: process.env.KV_REST_API_TOKEN,
  },
  routeRateLimit: {
    // Example route rate limits
    login: { attempts: 5, windowSeconds: 60 }, // 5 login attempts per minute
    register: { attempts: 3, windowSeconds: 60 }, // 3 register attempts per minute
    passwordReset: { attempts: 3, windowSeconds: 60 * 10 }, // 3 password reset attempts per 10 minutes
  },
  csrf: {
    enabled: true, // CSRF protection enabled by default
    secret: process.env.CSRF_SECRET || generateRandomSecret(32), // Fallback to random secret if not in env
  },
  passwordPepper: process.env.PASSWORD_PEPPER || generateRandomSecret(16), // Fallback to random pepper
  logger: consoleLogger, // Default to console logger
};

export function mergeConfig(
  userConfig: SpectraAuthConfig | undefined,
  defaultCfg: SpectraAuthConfig,
): Required<SpectraAuthConfig> {
  return {
    ...defaultCfg,
    ...(userConfig || {}),
  };
}

/**
 * Generates a random secret string (base64url encoded).
 * Used for CSRF secret and password pepper if not provided in environment variables.
 * @param lengthBytes Length of the secret in bytes.
 * @returns A base64url encoded random secret.
 */
function generateRandomSecret(lengthBytes: number): string {
  return base64Url.encode(getRandomValues(new Uint8Array(lengthBytes)));
}
