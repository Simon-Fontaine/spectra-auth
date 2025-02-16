import type { PrismaClient } from "@prisma/client";
import { Ratelimit } from "@upstash/ratelimit";
import {
  completeEmailChangeCore,
  completePasswordResetCore,
  createSessionCore,
  createVerificationCore,
  getSessionCore,
  initiateEmailChangeCore,
  initiatePasswordResetCore,
  loginUserCore,
  logoutUserCore,
  registerUserCore,
  useVerificationTokenCore,
  validateAndRotateSessionCore,
  validateSessionCore,
  verifyEmailCore,
} from "./auth";
import { buildConfig } from "./config";
import {
  type AegisAuthConfig,
  type CoreContext,
  type Endpoints,
  defaultEndpoints,
} from "./types";
import { parseRequest } from "./utils";

export class AegisAuth {
  private config: AegisAuthConfig;
  private prisma: PrismaClient;
  private endpoints: Endpoints = {};

  private async createContext(headers?: Headers): Promise<CoreContext> {
    const parsedRequest = headers
      ? await parseRequest(headers, this.config)
      : undefined;

    return {
      prisma: this.prisma,
      config: this.config,
      endpoints: this.endpoints,
      parsedRequest,
    };
  }

  private initializeEndpoints() {
    const { rateLimit } = this.config.protection;
    if (!rateLimit.enabled || !rateLimit.redis) return;

    for (const endpoint of defaultEndpoints) {
      const endpointConfig = rateLimit.endpoints[endpoint];
      if (!endpointConfig || !endpointConfig.enabled) continue;

      this.endpoints[endpoint] = new Ratelimit({
        redis: rateLimit.redis,
        limiter: Ratelimit.slidingWindow(
          endpointConfig.maxAttempts,
          `${endpointConfig.window} s`,
        ),
        prefix: `${rateLimit.prefix}:${endpoint}`,
      });
    }
  }

  constructor(prisma: PrismaClient, userConfig?: Partial<AegisAuthConfig>) {
    this.prisma = prisma;
    this.config = buildConfig(userConfig);
    this.initializeEndpoints();
  }

  getConfig() {
    return this.config;
  }

  async completeEmailChange(
    headers: Headers,
    options: Parameters<typeof completeEmailChangeCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return completeEmailChangeCore(ctx, options);
  }

  async completePasswordReset(
    headers: Headers,
    options: Parameters<typeof completePasswordResetCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return completePasswordResetCore(ctx, options);
  }

  async createSession(
    headers: Headers,
    options: Parameters<typeof createSessionCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return createSessionCore(ctx, options);
  }

  async createVerification(
    headers: Headers,
    options: Parameters<typeof createVerificationCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return createVerificationCore(ctx, options);
  }

  async getSession(
    headers: Headers,
    options: Parameters<typeof getSessionCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return getSessionCore(ctx, options);
  }

  async initiateEmailChange(
    headers: Headers,
    options: Parameters<typeof initiateEmailChangeCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return initiateEmailChangeCore(ctx, options);
  }

  async initiatePasswordReset(
    headers: Headers,
    options: Parameters<typeof initiatePasswordResetCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return initiatePasswordResetCore(ctx, options);
  }

  async loginUser(
    headers: Headers,
    options: Parameters<typeof loginUserCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return loginUserCore(ctx, options);
  }

  async logoutUser(headers: Headers) {
    const ctx = await this.createContext(headers);
    return logoutUserCore(ctx);
  }

  async registerUser(
    headers: Headers,
    options: Parameters<typeof registerUserCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return registerUserCore(ctx, options);
  }

  async useVerificationToken(
    headers: Headers,
    options: Parameters<typeof useVerificationTokenCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return useVerificationTokenCore(ctx, options);
  }

  async validateAndRotateSession(headers: Headers) {
    const ctx = await this.createContext(headers);
    return validateAndRotateSessionCore(ctx);
  }

  async validateSession(headers: Headers) {
    const ctx = await this.createContext(headers);
    return validateSessionCore(ctx);
  }

  async verifyEmail(
    headers: Headers,
    options: Parameters<typeof verifyEmailCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return verifyEmailCore(ctx, options);
  }
}
