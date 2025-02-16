import { Redis } from "@upstash/redis";
import { z } from "zod";
import { createTime } from "../utils";

export const configSchema = z.object({
  // Core Settings
  baseUrl: z.string().url().default("http://localhost:3000"),

  // Authentication Core
  auth: z
    .object({
      requireEmailVerification: z.boolean().default(true),
      maxSessionsPerUser: z.number().int().nonnegative().default(5),
      maxFailedAttempts: z.number().int().positive().default(5),
      lockoutDuration: z
        .number()
        .int()
        .positive()
        .default(createTime(15, "m").toSeconds()),
      password: z
        .object({
          hash: z
            .object({
              cost: z.number().int().positive().default(16384),
              blockSize: z.number().int().positive().default(16),
              parallelization: z.number().int().positive().default(1),
              keyLength: z.number().int().positive().default(64),
            })
            .default({}),
          rules: z
            .object({
              minLength: z.number().int().positive().default(8),
              maxLength: z.number().int().positive().default(32),
              requireLowercase: z.boolean().default(true),
              requireUppercase: z.boolean().default(true),
              requireNumber: z.boolean().default(true),
              requireSymbol: z.boolean().default(true),
            })
            .default({}),
        })
        .default({}),
      geo: z
        .object({
          enabled: z.boolean().default(false),
          maxmindClientId: z
            .string()
            .default(process.env.MAXMIND_CLIENT_ID || ""),
          maxmindLicenseKey: z
            .string()
            .default(process.env.MAXMIND_LICENSE_KEY || ""),
        })
        .default({}),
    })
    .default({}),

  // Security Features
  security: z
    .object({
      session: z
        .object({
          secret: z
            .string()
            .default(process.env.SESSION_TOKEN_SECRET || "change-me")
            .refine(
              (value) =>
                process.env.NODE_ENV !== "production" || value !== "change-me",
              {
                message: "Please set a secure session secret in production",
              },
            ),
          secretLength: z.number().int().positive().default(64),
          maxLifetime: z
            .number()
            .int()
            .positive()
            .default(createTime(30, "d").toSeconds()),
          refreshInterval: z
            .number()
            .int()
            .positive()
            .default(createTime(1, "h").toSeconds()),
          cookie: z
            .object({
              name: z.string().min(1).default("aegis.session"),
              maxAge: z
                .number()
                .int()
                .positive()
                .default(createTime(1, "w").toSeconds()),
              domain: z.string().optional(),
              path: z.string().default("/"),
              httpOnly: z.boolean().default(true),
              secure: z.boolean().default(true),
              sameSite: z
                .union([z.enum(["strict", "lax", "none"]), z.boolean()])
                .default("lax"),
            })
            .default({}),
        })
        .default({}),
      csrf: z
        .object({
          enabled: z.boolean().default(true),
          secret: z
            .string()
            .default(process.env.CSRF_TOKEN_SECRET || "change-me")
            .refine(
              (value) =>
                process.env.NODE_ENV !== "production" || value !== "change-me",
              {
                message: "Please set a secure CSRF secret in production",
              },
            ),
          secretLength: z.number().int().positive().default(32),
          cookie: z
            .object({
              name: z.string().min(1).default("aegis.csrf"),
              maxAge: z
                .number()
                .int()
                .positive()
                .default(createTime(1, "w").toSeconds()),
              domain: z.string().optional(),
              path: z.string().default("/"),
              httpOnly: z.boolean().default(true),
              secure: z.boolean().default(true),
              sameSite: z
                .union([z.enum(["strict", "lax", "none"]), z.boolean()])
                .default("lax"),
            })
            .default({}),
        })
        .default({}),
      verification: z
        .object({
          tokenLength: z.number().int().positive().default(32),
          tokenExpiry: z
            .number()
            .int()
            .positive()
            .default(createTime(1, "d").toSeconds()),
        })
        .default({}),
    })
    .default({}),

  // Protection Features
  protection: z
    .object({
      rateLimit: z
        .object({
          enabled: z.boolean().default(true),
          redis: z.instanceof(Redis).optional(),
          prefix: z.string().default("aegis:rate-limit"),
          endpoints: z
            .object({
              login: z
                .object({
                  enabled: z.boolean().default(true),
                  maxAttempts: z.number().int().positive().default(5),
                  window: z
                    .number()
                    .int()
                    .positive()
                    .default(createTime(15, "m").toSeconds()),
                })
                .default({}),
              register: z
                .object({
                  enabled: z.boolean().default(true),
                  maxAttempts: z.number().int().positive().default(3),
                  window: z
                    .number()
                    .int()
                    .positive()
                    .default(createTime(15, "m").toSeconds()),
                })
                .default({}),
              verifyEmail: z
                .object({
                  enabled: z.boolean().default(true),
                  maxAttempts: z.number().int().positive().default(3),
                  window: z
                    .number()
                    .int()
                    .positive()
                    .default(createTime(15, "m").toSeconds()),
                })
                .default({}),
              initiatePasswordReset: z
                .object({
                  enabled: z.boolean().default(true),
                  maxAttempts: z.number().int().positive().default(3),
                  window: z
                    .number()
                    .int()
                    .positive()
                    .default(createTime(15, "m").toSeconds()),
                })
                .default({}),
              completePasswordReset: z
                .object({
                  enabled: z.boolean().default(true),
                  maxAttempts: z.number().int().positive().default(3),
                  window: z
                    .number()
                    .int()
                    .positive()
                    .default(createTime(15, "m").toSeconds()),
                })
                .default({}),
              initiateEmailChange: z
                .object({
                  enabled: z.boolean().default(true),
                  maxAttempts: z.number().int().positive().default(3),
                  window: z
                    .number()
                    .int()
                    .positive()
                    .default(createTime(15, "m").toSeconds()),
                })
                .default({}),
              completeEmailChange: z
                .object({
                  enabled: z.boolean().default(true),
                  maxAttempts: z.number().int().positive().default(3),
                  window: z
                    .number()
                    .int()
                    .positive()
                    .default(createTime(15, "m").toSeconds()),
                })
                .default({}),
            })
            .default({}),
        })
        .default({}),
    })
    .default({}),

  // Communication
  communication: z
    .object({
      email: z
        .object({
          from: z.string().email().default("no-reply@example.com"),
          resendApiKey: z.string().default(process.env.RESEND_API_KEY || ""),
          templates: z
            .object({
              verifyEmail: z
                .function()
                .args(
                  z.object({
                    token: z.string(),
                    toEmail: z.string(),
                    callbackUrl: z.string(),
                  }),
                )
                .returns(z.string())
                .optional(),
              passwordReset: z
                .function()
                .args(
                  z.object({
                    token: z.string(),
                    toEmail: z.string(),
                    callbackUrl: z.string(),
                  }),
                )
                .returns(z.string())
                .optional(),
            })
            .default({}),
        })
        .default({}),
    })
    .default({}),
});
