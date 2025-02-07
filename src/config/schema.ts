import { z } from "zod";

/**
 * Zod schema for validating the SpectraAuth configuration object.
 * This schema defines the expected structure and types of the configuration
 * that can be passed to `initSpectraAuth()`.
 */
export const configSchema = z.object({
  logger: z.object({}).optional(), //  Custom logger instance (if provided) - details are handled by LoggerInterface type
  securityEventLogger: z.object({}).optional(), // Custom security event logger - same as above

  session: z
    .object({
      cookieName: z.string().default("spectra.sessionToken"),
      maxAgeSec: z
        .number()
        .int()
        .positive()
        .default(30 * 24 * 60 * 60), // Seconds
      tokenLengthBytes: z.number().int().positive().default(32),
      tokenPrefixLengthBytes: z.number().int().positive().default(8),
      tokenSecret: z.string().min(16), // Ensure token secret is at least 16 chars long
      csrfSecret: z.string().min(16), // Ensure CSRF secret is also strong
      cookieSecure: z.boolean().default(process.env.NODE_ENV === "production"),
      cookieSameSite: z.enum(["Strict", "Lax", "None"]).default("Lax"),
      cookieHttpOnly: z.boolean().default(true),
      maxSessionsPerUser: z.number().int().positive().optional(), // Optional limit on concurrent sessions
    })
    .required(),

  rateLimit: z
    .object({
      disable: z.boolean().default(false),
      kvRestApiUrl: z.string().optional(), // Required if rate limiting is enabled
      kvRestApiToken: z.string().optional(), // Required if rate limiting is enabled
      loginRoute: z
        .object({
          enabled: z.boolean().default(true),
          attempts: z.number().int().positive().default(5),
          windowSeconds: z
            .number()
            .int()
            .positive()
            .default(60 * 5),
        })
        .required(),
      registerRoute: z
        .object({
          enabled: z.boolean().default(true),
          attempts: z.number().int().positive().default(3),
          windowSeconds: z
            .number()
            .int()
            .positive()
            .default(60 * 10),
        })
        .required(),
      passwordResetRoute: z
        .object({
          enabled: z.boolean().default(true),
          attempts: z.number().int().positive().default(3),
          windowSeconds: z
            .number()
            .int()
            .positive()
            .default(60 * 15),
        })
        .required(),
      // Add more routes as needed following the pattern above
    })
    .required(),

  accountLock: z
    .object({
      enabled: z.boolean().default(true),
      threshold: z.number().int().positive().default(5),
      durationMs: z
        .number()
        .int()
        .positive()
        .default(60 * 60 * 1000), // Milliseconds
    })
    .required(),
  passwordHashOptions: z.object({
    time: z.number().int().positive().default(2),
    mem: z.number().int().positive().default(65536),
    parallelism: z.number().int().positive().default(2),
    hashLen: z.number().int().positive().default(32),
  }),
  passwordPepper: z
    .string()
    .min(16)
    .default("default-insecure-password-pepper"), // Ensure pepper is strong, provide default

  csrf: z
    .object({
      enabled: z.boolean().default(true),
      cookieName: z.string().default("spectra.csrfToken"),
      headerName: z.string().default("X-CSRF-Token"),
      formFieldName: z.string().default("_csrf"),
      tokenLengthBytes: z.number().int().positive().default(32),
      cookieSecure: z.boolean().default(process.env.NODE_ENV === "production"),
      cookieHttpOnly: z.boolean().default(true),
      cookieSameSite: z.enum(["strict", "lax", "none"]).default("strict"), // Strict for CSRF
      maxAgeSec: z
        .number()
        .int()
        .positive()
        .default(2 * 60 * 60), // CSRF token max age - shorter than session
    })
    .required(),
});

/**
 * Type representing the validated configuration, inferred from the schema.
 */
export type ValidatedSpectraAuthConfig = z.infer<typeof configSchema>;

/**
 * Validates the provided configuration object against the schema.
 *
 * @param config - The configuration object to validate.
 * @throws Error if the configuration is invalid, with details from Zod.
 * @returns The validated configuration object if it is valid.
 */
export function validateConfig(config: unknown): ValidatedSpectraAuthConfig {
  return configSchema.parse(config); // parse() will throw a ZodError if validation fails
}
