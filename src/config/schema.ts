import { z } from "zod";

const routeRateLimitSchema = z
  .object({
    attempts: z.number().int().positive(),
    windowSeconds: z.number().int().positive(),
  })
  .optional();

export const configSchema = z.object({
  session: z.object({
    maxAgeSec: z.number().int().positive(),
    updateAgeSec: z.number().int().positive(),
    maxSessionsPerUser: z.number().int().nonnegative(),
    cookieSecure: z.boolean().default(process.env.NODE_ENV === "production"),
    cookieSameSite: z.enum(["lax", "strict", "none"]).default("lax"),
  }),
  accountLock: z.object({
    threshold: z.number().int().positive(),
    durationMs: z.number().int().positive(),
  }),
  rateLimit: z.object({
    disable: z.boolean().optional(),
    kvRestApiUrl: z.string().optional(),
    kvRestApiToken: z.string().optional(),
  }),
  routeRateLimit: z
    .object({
      login: routeRateLimitSchema,
      register: routeRateLimitSchema,
      passwordReset: routeRateLimitSchema,
    })
    .optional(),
  csrf: z.object({
    enabled: z.boolean().default(true),
    secret: z.string().min(32), // Minimum 32 chars for secret
  }),
  passwordPepper: z.string().min(16), // Minimum pepper length
  logger: z.object({
    info: z
      .function()
      .args(z.string(), z.record(z.unknown()).optional())
      .returns(z.void()),
    warn: z
      .function()
      .args(z.string(), z.record(z.unknown()).optional())
      .returns(z.void()),
    error: z
      .function()
      .args(z.string(), z.record(z.unknown()).optional())
      .returns(z.void()),
    securityEvent: z
      .function()
      .args(z.string(), z.record(z.unknown()))
      .returns(z.void()),
  }),
});

export type ConfigSchema = z.infer<typeof configSchema>;

export function validateConfig(
  config: unknown,
): asserts config is ConfigSchema {
  configSchema.parse(config);
}
