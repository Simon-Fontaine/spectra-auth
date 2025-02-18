import type { PrismaClient } from "@prisma/client";
import { Ratelimit } from "@upstash/ratelimit";
import {
  addRoleToUserCore,
  banUserCore,
  completeAccountDeletionCore,
  completeEmailChangeCore,
  completePasswordResetCore,
  createRoleCore,
  createSessionCore,
  createVerificationCore,
  deleteRoleCore,
  getRoleByIdCore,
  getRolesCore,
  getSessionCore,
  initiateAccountDeletionCore,
  initiateEmailChangeCore,
  initiatePasswordResetCore,
  loginUserCore,
  logoutUserCore,
  registerUserCore,
  removeRoleFromUserCore,
  unbanUserCore,
  updateRoleCore,
  useVerificationTokenCore,
  validateAndRotateSessionCore,
  validateSessionCore,
  verifyEmailCore,
} from "./auth";
import { type AegisAuthConfig, buildConfig } from "./config";
import { type CoreContext, type Endpoints, defaultEndpoints } from "./types";
import { parseRequest } from "./utils";

export class AegisAuth {
  private config: AegisAuthConfig;
  private prisma: PrismaClient;
  private endpoints: Endpoints = {};

  private async createContext(headers?: Headers): Promise<CoreContext> {
    const parsedRequest = await parseRequest(
      headers || new Headers(),
      this.config,
    );

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

    try {
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
    } catch (error) {
      this.config.logger?.error("Failed to initialize endpoints.", {
        error: error instanceof Error ? error.message : String(error),
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

  async banUser(headers: Headers, options: Parameters<typeof banUserCore>[1]) {
    const ctx = await this.createContext(headers);
    return banUserCore(ctx, options);
  }

  async completeAccountDeletion(
    headers: Headers,
    options: Parameters<typeof completeAccountDeletionCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return completeAccountDeletionCore(ctx, options);
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

  async initiateAccountDeletion(headers: Headers) {
    const ctx = await this.createContext(headers);
    return initiateAccountDeletionCore(ctx);
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

  async unbanUser(
    headers: Headers,
    options: Parameters<typeof unbanUserCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return unbanUserCore(ctx, options);
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

  // Role management
  async createRole(
    headers: Headers,
    data: Parameters<typeof createRoleCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return createRoleCore(ctx, data);
  }

  async updateRole(
    headers: Headers,
    data: Parameters<typeof updateRoleCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return updateRoleCore(ctx, data);
  }

  async deleteRole(
    headers: Headers,
    data: Parameters<typeof deleteRoleCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return deleteRoleCore(ctx, data);
  }

  async addRoleToUser(
    headers: Headers,
    data: Parameters<typeof addRoleToUserCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return addRoleToUserCore(ctx, data);
  }

  async removeRoleFromUser(
    headers: Headers,
    data: Parameters<typeof removeRoleFromUserCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return removeRoleFromUserCore(ctx, data);
  }

  async getRoles(headers: Headers) {
    const ctx = await this.createContext(headers);
    return getRolesCore(ctx);
  }

  async getRoleById(
    headers: Headers,
    data: Parameters<typeof getRoleByIdCore>[1],
  ) {
    const ctx = await this.createContext(headers);
    return getRoleByIdCore(ctx, data);
  }
}
