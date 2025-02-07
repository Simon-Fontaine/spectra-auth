import { z } from "zod";

const configSchema = z.object({
  session: z.object({
    maxAgeSec: z.number(),
    updateAgeSec: z.number(),
    maxSessionsPerUser: z.number(),
  }),
  accountLock: z.object({
    threshold: z.number(),
    durationMs: z.number(),
  }),
  rateLimit: z.object({
    disable: z.boolean().optional(),
    kvRestApiUrl: z.string().optional(),
    kvRestApiToken: z.string().optional(),
  }),
  routeRateLimit: z.object({
    login: z
      .object({
        attempts: z.number(),
        windowSeconds: z.number(),
      })
      .optional(),
    register: z
      .object({
        attempts: z.number(),
        windowSeconds: z.number(),
      })
      .optional(),
    passwordReset: z
      .object({
        attempts: z.number(),
        windowSeconds: z.number(),
      })
      .optional(),
  }),
  csrf: z.object({
    enabled: z.boolean(),
    secret: z.string(),
  }),
  passwordPepper: z.string(),
  logger: z.object({
    info: z
      .function()
      .args(z.string(), z.record(z.unknown()))
      .returns(z.void()),
    warn: z
      .function()
      .args(z.string(), z.record(z.unknown()))
      .returns(z.void()),
    error: z
      .function()
      .args(z.string(), z.record(z.unknown()))
      .returns(z.void()),
    securityEvent: z
      .function()
      .args(z.string(), z.record(z.unknown()))
      .returns(z.void()),
  }),
});

export function validateConfig(config: unknown) {
  return configSchema.parse(config);
}
