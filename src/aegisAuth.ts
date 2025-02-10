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
import type { AuthHeaders, Limiters } from "./types";
import { parseRequest } from "./utils";

export class AegisAuth {
  private prisma: PrismaClient;
  private config: Required<AegisAuthConfig>;
  private limiters: Limiters = {};
  private createContext(request: {
    headers: AuthHeaders;
  }) {
    return {
      prisma: this.prisma,
      config: this.config,
      limiters: this.limiters,
      parsedRequest: parseRequest(request, this.config),
    };
  }

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
    request: Parameters<typeof completePasswordResetCore>[1],
    input: Parameters<typeof completePasswordResetCore>[2],
  ) {
    return completePasswordResetCore(
      this.createContext(request),
      request,
      input,
    );
  }

  async createSession(
    request: Parameters<typeof createSessionCore>[1],
    input: Parameters<typeof createSessionCore>[2],
  ) {
    return createSessionCore(this.createContext(request), request, input);
  }

  async createVerification(
    input: Parameters<typeof createVerificationCore>[1],
  ) {
    return createVerificationCore(this.createContext(), input);
  }

  async initiatePasswordReset(
    request: Parameters<typeof initiatePasswordResetCore>[1],
    input: Parameters<typeof initiatePasswordResetCore>[2],
  ) {
    return initiatePasswordResetCore(
      this.createContext(request),
      request,
      input,
    );
  }

  async loginUser(
    request: Parameters<typeof loginUserCore>[1],
    input: Parameters<typeof loginUserCore>[2],
  ) {
    return loginUserCore(this.createContext(request), request, input);
  }

  async logoutUser(input: Parameters<typeof logoutUserCore>[1]) {
    return logoutUserCore(this.createContext(), input);
  }

  async registerUser(
    request: Parameters<typeof registerUserCore>[1],
    input: Parameters<typeof registerUserCore>[2],
  ) {
    return registerUserCore(this.createContext(request), request, input);
  }

  async revokeAllSessionsForUser(
    input: Parameters<typeof revokeAllSessionsForUserCore>[1],
  ) {
    return revokeAllSessionsForUserCore(this.createContext(), input);
  }

  async revokeSession(input: Parameters<typeof revokeSessionCore>[1]) {
    return revokeSessionCore(this.createContext(), input);
  }

  async useVerificationToken(
    input: Parameters<typeof useVerificationTokenCore>[1],
  ) {
    return useVerificationTokenCore(this.createContext(), input);
  }

  async validateAndRotateSession(
    request: Parameters<typeof validateAndRotateSessionCore>[1],
    input: Parameters<typeof validateAndRotateSessionCore>[2],
  ) {
    return validateAndRotateSessionCore(
      this.createContext(request),
      request,
      input,
    );
  }

  async verifyEmail(
    request: Parameters<typeof verifyEmailCore>[1],
    input: Parameters<typeof verifyEmailCore>[2],
  ) {
    return verifyEmailCore(this.createContext(request), request, input);
  }
}
