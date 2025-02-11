import { z } from "zod";
import { ConsoleLogger, createTime } from "../utils";

export const configSchema = z.object({
  logger: z
    .object({
      debug: z
        .function()
        .args(z.string(), z.record(z.string(), z.unknown()).optional())
        .returns(z.void()),
      info: z
        .function()
        .args(z.string(), z.record(z.string(), z.unknown()).optional())
        .returns(z.void()),
      warn: z
        .function()
        .args(z.string(), z.record(z.string(), z.unknown()).optional())
        .returns(z.void()),
      error: z
        .function()
        .args(z.string(), z.record(z.string(), z.unknown()).optional())
        .returns(z.void()),
      securityEvent: z
        .function()
        .args(z.string(), z.record(z.string(), z.unknown()).optional())
        .returns(z.void()),
    })
    .default(new ConsoleLogger()),

  // Auth Session
  session: z.object({
    cookieName: z.string().default("aegis.sessionToken"),
    maxAgeSeconds: z
      .number()
      .int()
      .positive()
      .default(createTime(7, "d").toSeconds()),
    tokenLengthBytes: z.number().int().positive().default(64),
    tokenSecret: z
      .string()
      .refine(
        (val) => process.env.NODE_ENV !== "production" || val !== "change-me",
        {
          message:
            "SESSION_TOKEN_SECRET must be set to a secure value in production.",
        },
      )
      .default(process.env.SESSION_TOKEN_SECRET || "change-me"),
    cookieSecure: z.boolean().default(process.env.NODE_ENV === "production"),
    cookieSameSite: z.enum(["strict", "lax", "none"]).default("lax"),
    cookieHttpOnly: z.boolean().default(true),
    maxSessionsPerUser: z.number().int().positive().default(5),
    rollingIntervalSeconds: z
      .number()
      .int()
      .nonnegative()
      .default(createTime(1, "h").toSeconds()),
  }),

  // CSRF Protection
  csrf: z.object({
    enabled: z.boolean().default(true),
    cookieName: z.string().default("aegis.csrfToken"),
    maxAgeSeconds: z
      .number()
      .int()
      .positive()
      .default(createTime(2, "h").toSeconds()),
    tokenLengthBytes: z.number().int().positive().default(32),
    tokenSecret: z
      .string()
      .refine(
        (val) => process.env.NODE_ENV !== "production" || val !== "change-me",
        { message: "CSRF_SECRET must be set to a secure value in production." },
      )
      .default(process.env.CSRF_SECRET || "change-me"),
    cookieSecure: z.boolean().default(process.env.NODE_ENV === "production"),
    cookieSameSite: z.enum(["strict", "lax", "none"]).default("lax"),
    cookieHttpOnly: z.boolean().default(false),
  }),

  // Verification
  verification: z.object({
    tokenLengthBytes: z.number().int().positive().default(32),
    tokenExpirySeconds: z
      .number()
      .int()
      .positive()
      .default(createTime(1, "h").toSeconds()),
  }),

  // Auth Rate Limiting
  rateLimiting: z.object({
    enabled: z.boolean().default(true),
    kvRestApiUrl: z.string().optional(),
    kvRestApiToken: z.string().optional(),
    // Per route rate limits
    login: z.object({
      enabled: z.boolean().default(true),
      maxRequests: z.number().int().positive().default(5),
      windowSeconds: z
        .number()
        .int()
        .positive()
        .default(createTime(10, "m").toSeconds()),
    }),
    register: z.object({
      enabled: z.boolean().default(true),
      maxRequests: z.number().int().positive().default(3),
      windowSeconds: z
        .number()
        .int()
        .positive()
        .default(createTime(10, "m").toSeconds()),
    }),
    verifyEmail: z.object({
      enabled: z.boolean().default(true),
      maxRequests: z.number().int().positive().default(3),
      windowSeconds: z
        .number()
        .int()
        .positive()
        .default(createTime(15, "m").toSeconds()),
    }),
    forgotPassword: z.object({
      enabled: z.boolean().default(true),
      maxRequests: z.number().int().positive().default(3),
      windowSeconds: z
        .number()
        .int()
        .positive()
        .default(createTime(15, "m").toSeconds()),
    }),
    passwordReset: z.object({
      enabled: z.boolean().default(true),
      maxRequests: z.number().int().positive().default(3),
      windowSeconds: z
        .number()
        .int()
        .positive()
        .default(createTime(15, "m").toSeconds()),
    }),
  }),

  // Account Security
  accountSecurity: z.object({
    requireEmailVerification: z.boolean().default(true),
    maxFailedLogins: z.number().int().nonnegative().default(5),
    lockoutDurationSeconds: z
      .number()
      .int()
      .positive()
      .default(createTime(15, "m").toSeconds()),
    passwordHashing: z.object({
      costFactor: z.number().int().positive().default(16384),
      blockSize: z.number().int().positive().default(16),
      parallelization: z.number().int().positive().default(1),
      derivedKeyLength: z.number().int().positive().default(64),
    }),
  }),

  // Email
  email: z
    .object({
      resendApiKey: z.string().optional(),
      from: z.string().default("no-reply@example.com"),
      baseUrl: z.string().url().default("http://localhost:3000"),
      templates: z
        .object({
          verification: z
            .function()
            .args(z.object({ token: z.string(), toEmail: z.string() }))
            .returns(z.string()) // Expect HTML string
            .optional(),
          passwordReset: z
            .function()
            .args(z.object({ token: z.string(), toEmail: z.string() }))
            .returns(z.string())
            .optional(),
        })
        .optional(),
    })
    .optional(),
});

export type AegisAuthConfig = z.infer<typeof configSchema>;
