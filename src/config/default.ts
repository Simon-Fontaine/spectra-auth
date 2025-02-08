import { ConsoleLogger, createTime } from "../utils";
import type { SpectraAuthConfig } from "./schema";

export const defaultConfig = {
  logger: new ConsoleLogger(),

  // Auth Session
  session: {
    cookieName: "spectra.sessionToken",
    maxAgeSeconds: createTime(7, "d").toSeconds(),
    tokenLengthBytes: 64, // 64 bytes = 512 bits
    tokenPrefixLengthBytes: 16, // 16 bytes = 128 bits
    tokenSecret: process.env.SESSION_TOKEN_SECRET || "change-me",
    cookieSecure: process.env.NODE_ENV === "production",
    cookieSameSite: "lax", // "strict" | "lax" | "none"
    cookieHttpOnly: true,
    maxSessionsPerUser: 5,
    rollingIntervalSeconds: createTime(1, "h").toSeconds(), // 0 to disable
  },

  // CSRF Protection
  csrf: {
    enabled: true,
    cookieName: "spectra.csrfToken",
    maxAgeSeconds: createTime(2, "h").toSeconds(),
    tokenLengthBytes: 32, // 32 bytes = 256 bits
    tokenSecret: process.env.CSRF_SECRET || "change-me",
    cookieSecure: process.env.NODE_ENV === "production",
    cookieSameSite: "lax", // "strict" | "lax" | "none"
    cookieHttpOnly: false, // client-side JS needs access
  },

  // Verification
  verification: {
    tokenLengthBytes: 32, // 32 bytes = 256 bits
    tokenExpirySeconds: createTime(1, "h").toSeconds(),
  },

  // Auth Rate Limiting
  rateLimiting: {
    enabled: true,
    kvRestApiUrl: process.env.KV_REST_API_URL,
    kvRestApiToken: process.env.KV_REST_API_TOKEN,
    // Per route rate limits
    login: {
      enabled: true,
      maxRequests: 5,
      windowSeconds: createTime(10, "m").toSeconds(),
    },
    register: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: createTime(10, "m").toSeconds(),
    },
    verifyEmail: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: createTime(15, "m").toSeconds(),
    },
    forgotPassword: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: createTime(15, "m").toSeconds(),
    },
    passwordReset: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: createTime(15, "m").toSeconds(),
    },
  },

  // Account Security
  accountSecurity: {
    requireEmailVerification: true,
    maxFailedLogins: 5, // 0 to disable
    lockoutDurationSeconds: createTime(15, "m").toSeconds(),
    passwordHashing: {
      costFactor: 16384, // cost factor
      blockSize: 16, // block size
      parallelization: 1, // parallelization
      derivedKeyLength: 64, // key length
    },
  },
} as SpectraAuthConfig;
