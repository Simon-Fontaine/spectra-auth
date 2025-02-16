import { Redis } from "@upstash/redis";
import { z } from "zod";
import { createTime } from "../utils";

const authSchema = z.object({
  registration: z.object({
    enabled: z.boolean().default(true),
    requireEmailVerification: z.boolean().default(true),
  }),
  login: z.object({
    maxFailedAttempts: z.number().int().positive().default(5),
    lockoutDurationSeconds: z
      .number()
      .int()
      .positive()
      .default(createTime(15, "m").toSeconds()), // 15 min default
  }),
  session: z.object({
    maxSessionsPerUser: z.number().int().nonnegative().default(5),
  }),
  password: z.object({
    hash: z.object({
      cost: z.number().int().positive().default(16384),
      blockSize: z.number().int().positive().default(16),
      parallelization: z.number().int().positive().default(1),
      keyLength: z.number().int().positive().default(64),
    }),
    rules: z.object({
      minLength: z.number().int().positive().default(8),
      maxLength: z.number().int().positive().default(32),
      requireLowercase: z.boolean().default(true),
      requireUppercase: z.boolean().default(true),
      requireNumber: z.boolean().default(true),
      requireSymbol: z.boolean().default(true),
    }),
  }),
  geo: z.object({
    enabled: z.boolean().default(false),
    maxmindClientId: z.string().default(process.env.MAXMIND_CLIENT_ID || ""),
    maxmindLicenseKey: z
      .string()
      .default(process.env.MAXMIND_LICENSE_KEY || ""),
    maxmindHost: z.string().default("geolite.info"),
  }),
});

const securitySchema = z.object({
  session: z.object({
    secret: z.string().default(process.env.SESSION_TOKEN_SECRET || "change-me"),
    secretLength: z.number().int().positive().default(64),
    maxLifetimeSeconds: z
      .number()
      .int()
      .positive()
      // 30 days default
      .default(createTime(30, "d").toSeconds()),
    refreshIntervalSeconds: z
      .number()
      .int()
      .positive()
      // 1 hour default
      .default(createTime(1, "h").toSeconds()),
    cookie: z.object({
      name: z.string().min(1).default("aegis.session"),
      maxAge: z
        .number()
        .int()
        .positive()
        .default(createTime(1, "w").toSeconds()), // 1 week
      domain: z.string().optional(),
      path: z.string().default("/"),
      httpOnly: z.boolean().default(true),
      secure: z.boolean().default(true),
      sameSite: z
        .union([z.enum(["strict", "lax", "none"]), z.boolean()])
        .default("lax"),
    }),
  }),
  csrf: z.object({
    enabled: z.boolean().default(true),
    secret: z.string().default(process.env.CSRF_TOKEN_SECRET || "change-me"),
    secretLength: z.number().int().positive().default(32),
    cookie: z.object({
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
    }),
  }),
  verification: z.object({
    tokenLength: z.number().int().positive().default(32),
    tokenExpirySeconds: z
      .number()
      .int()
      .positive()
      .default(createTime(1, "d").toSeconds()), // 24 hours
  }),
});

const protectionSchema = z.object({
  rateLimit: z.object({
    enabled: z.boolean().default(true),
    redis: z.instanceof(Redis).optional(),
    prefix: z.string().default("aegis:rate-limit"),
    endpoints: z.object({
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
    }),
  }),
});

const communicationSchema = z.object({
  email: z.object({
    from: z.string().email().default("no-reply@example.com"),
    resendApiKey: z.string().default(process.env.RESEND_API_KEY || ""),
    templates: z.object({
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
    }),
  }),
});

export const configSchema = z.object({
  core: z.object({
    baseUrl: z.string().url().default("http://localhost:3000"),
  }),
  auth: authSchema,
  security: securitySchema,
  protection: protectionSchema,
  communication: communicationSchema,
});
