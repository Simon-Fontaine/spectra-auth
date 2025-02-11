import { ConsoleLogger, createTime } from "../utils";
import type { AegisAuthConfig } from "./schema";

export const defaultConfig = {
  logger: new ConsoleLogger(),

  // Auth Session
  session: {
    cookieName: "aegis.sessionToken",
    maxAgeSeconds: createTime(7, "d").toSeconds(),
    tokenLengthBytes: 64, // 64 bytes = 512 bits
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
    cookieName: "aegis.csrfToken",
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
    initiatePasswordReset: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: createTime(15, "m").toSeconds(),
    },
    completePasswordReset: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: createTime(15, "m").toSeconds(),
    },
    initiateEmailChange: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: createTime(15, "m").toSeconds(),
    },
    completeEmailChange: {
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

  // Email
  email: {
    baseUrl: "http://localhost:3000",
    resendApiKey: process.env.RESEND_API_KEY || "",
    from: process.env.EMAIL_FROM || "no-reply@example.com",
    templates: {
      // verification: ({ token, toEmail }) => {
      //   return `
      //   <html>
      //     <body>
      //       <h1>Verify Your Email</h1>
      //       <h2>Hi ${toEmail},</h2>
      //       <p>Here is a custom template for verifying your email:</p>
      //       <a href="http://localhost:3000/verify-email?token=${token}">Verify Email</a>
      //     </body>
      //   </html>
      //   `;
      // },
    },
  },
} as AegisAuthConfig;
