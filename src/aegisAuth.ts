import type { PrismaClient } from "@prisma/client";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import _ from "lodash";
import { ZodError } from "zod";
import {
  completePasswordReset as completePasswordResetCore,
  createSession as createSessionCore,
  createVerification as createVerificationCore,
  initiatePasswordReset as initiatePasswordResetCore,
  loginUser as loginUserCore,
  logoutUser as logoutUserCore,
  registerUser as registerUserCore,
  revokeAllSessionsForUser as revokeAllSessionsForUserCore,
  revokeSession as revokeSessionCore,
  useVerificationToken as useVerificationTokenCore,
  validateAndRotateSession as validateAndRotateSessionCore,
  verifyEmail as verifyEmailCore,
} from "./actions";
import { type AegisAuthConfig, configSchema, defaultConfig } from "./config";
import { ConfigurationError } from "./errors/config";
import type { Limiters } from "./types";

export class AegisAuth {
  private prisma: PrismaClient;
  private config: Required<AegisAuthConfig>;
  private limiters: Limiters = {};

  constructor(prisma: PrismaClient, userConfig?: AegisAuthConfig) {
    this.prisma = prisma;
    const mergedConfig = _.defaultsDeep(userConfig, defaultConfig);
    try {
      configSchema.parse(mergedConfig);
    } catch (error) {
      if (error instanceof ZodError) {
        throw new ConfigurationError(
          error.errors
            .map((e) => `${e.path.join(".")}: ${e.message}`)
            .join("; "),
        );
      }
      throw new ConfigurationError(
        (error as Error).message ?? "Unknown configuration error",
      );
    }
    this.config = mergedConfig as Required<AegisAuthConfig>;

    // Initialize rate limiters ONCE
    if (this.config.rateLimiting.enabled) {
      const redis = new Redis({
        url: this.config.rateLimiting.kvRestApiUrl,
        token: this.config.rateLimiting.kvRestApiToken,
      });

      const routes = [
        "login",
        "register",
        "verifyEmail",
        "forgotPassword",
        "passwordReset",
      ] as const;

      for (const route of routes) {
        const routeConfig = this.config.rateLimiting[route];
        if (routeConfig.enabled) {
          this.limiters[route] = new Ratelimit({
            redis,
            limiter: Ratelimit.slidingWindow(
              routeConfig.maxRequests,
              `${routeConfig.windowSeconds} s`,
            ),
            prefix: `aegis-route:${route}:`,
          });
        }
      }
    }
  }

  async completePasswordReset(
    options: Parameters<typeof completePasswordResetCore>[0]["options"],
  ) {
    return completePasswordResetCore({
      options,
      prisma: this.prisma,
      config: this.config,
      limiters: this.limiters,
    });
  }

  async createSession(
    options: Parameters<typeof createSessionCore>[0]["options"],
  ) {
    return createSessionCore({
      options,
      prisma: this.prisma,
      config: this.config,
    });
  }

  async createVerification(
    options: Parameters<typeof createVerificationCore>[0]["options"],
  ) {
    return createVerificationCore({
      options,
      prisma: this.prisma,
      config: this.config,
    });
  }

  async initiatePasswordReset(
    options: Parameters<typeof initiatePasswordResetCore>[0]["options"],
  ) {
    return initiatePasswordResetCore({
      options,
      prisma: this.prisma,
      config: this.config,
      limiters: this.limiters,
    });
  }

  async loginUser(options: Parameters<typeof loginUserCore>[0]["options"]) {
    return loginUserCore({
      options,
      prisma: this.prisma,
      config: this.config,
      limiters: this.limiters,
    });
  }

  async logoutUser(sessionToken: string) {
    return logoutUserCore({
      sessionToken,
      prisma: this.prisma,
      config: this.config,
    });
  }

  async registerUser(
    options: Parameters<typeof registerUserCore>[0]["options"],
  ) {
    return registerUserCore({
      options,
      prisma: this.prisma,
      config: this.config,
      limiters: this.limiters,
    });
  }

  async revokeAllSessionsForUser(
    options: Parameters<typeof revokeAllSessionsForUserCore>[0]["options"],
  ) {
    return revokeAllSessionsForUserCore({
      options,
      prisma: this.prisma,
      config: this.config,
    });
  }

  async revokeSession(
    options: Parameters<typeof revokeSessionCore>[0]["options"],
  ) {
    return revokeSessionCore({
      options,
      prisma: this.prisma,
      config: this.config,
    });
  }

  async useVerificationToken(
    options: Parameters<typeof useVerificationTokenCore>[0]["options"],
  ) {
    return useVerificationTokenCore({
      options,
      prisma: this.prisma,
      config: this.config,
    });
  }

  async validateAndRotateSession(
    options: Parameters<typeof validateAndRotateSessionCore>[0]["options"],
  ) {
    return validateAndRotateSessionCore({
      options,
      prisma: this.prisma,
      config: this.config,
    });
  }

  async verifyEmail(options: Parameters<typeof verifyEmailCore>[0]["options"]) {
    return verifyEmailCore({
      options,
      prisma: this.prisma,
      config: this.config,
      limiters: this.limiters,
    });
  }
}
