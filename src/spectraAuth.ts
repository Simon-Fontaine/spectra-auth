import type { PrismaClient } from "@prisma/client";
import _ from "lodash";
import {
  completePasswordReset as completePasswordResetCore,
  createSession as createSessionCore,
  createVerification as createVerificationCore,
  initiatePasswordReset as initiatePasswordResetCore,
  loginUser as loginUserCore,
  logoutUser as logoutUserCore,
  registerUser as registerUserCore,
  revokeSession as revokeSessionCore,
  useVerificationToken as useVerificationTokenCore,
  validateSession as validateSessionCore,
  verifyEmail as verifyEmailCore,
} from "./actions";
import { type AegisAuthConfig, configSchema, defaultConfig } from "./config";
import { ConfigurationError } from "./errors/config";

export class AegisAuth {
  private prisma: PrismaClient;
  private config: Required<AegisAuthConfig>;

  constructor(prisma: PrismaClient, userConfig?: AegisAuthConfig) {
    this.prisma = prisma;
    const mergedConfig = _.defaultsDeep(userConfig, defaultConfig);
    try {
      configSchema.parse(mergedConfig);
    } catch (error) {
      throw new ConfigurationError((error as Error).message ?? undefined);
    }
    this.config = mergedConfig as Required<AegisAuthConfig>;
  }

  async completePasswordReset(
    options: Parameters<typeof completePasswordResetCore>[0]["options"],
  ) {
    return completePasswordResetCore({
      options,
      prisma: this.prisma,
      config: this.config,
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
    });
  }

  async loginUser(options: Parameters<typeof loginUserCore>[0]["options"]) {
    return loginUserCore({
      options,
      prisma: this.prisma,
      config: this.config,
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

  async validateSession(
    options: Parameters<typeof validateSessionCore>[0]["options"],
  ) {
    return validateSessionCore({
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
    });
  }
}
