import type { PrismaClient } from "@prisma/client";
import { Ratelimit } from "@upstash/ratelimit";
import {
  banUser as banUserCore,
  completeEmailChange as completeEmailChangeCore,
  completePasswordReset as completePasswordResetCore,
  createSession as createSessionCore,
  createVerification as createVerificationCore,
  initiateEmailChange as initiateEmailChangeCore,
  initiatePasswordReset as initiatePasswordResetCore,
  loginUser as loginUserCore,
  logoutUser as logoutUserCore,
  registerUser as registerUserCore,
  revokeAllSessionsForUser as revokeAllSessionsForUserCore,
  revokeSession as revokeSessionCore,
  unbanUser as unbanUserCore,
  updateUserRoles as updateUserRolesCore,
  useVerificationToken as useVerificationTokenCore,
  validateAndRotateSession as validateAndRotateSessionCore,
  verifyEmail as verifyEmailCore,
} from "./actions";
import { type AegisAuthConfig, buildConfig } from "./config";
import type { AuthHeaders, CoreContext, Limiters } from "./types";
import { parseRequest } from "./utils";

/**
 * AegisAuth is the main class for the authentication library.
 * It sets up the configuration, initializes rate limiters, and exposes methods for registration, login, session management, etc.
 */
export class AegisAuth {
  private prisma: PrismaClient;
  private config: AegisAuthConfig;
  private limiters: Limiters = {};

  /** Creates a bare-bones context (no request). */
  private createBaseContext(): CoreContext {
    return {
      prisma: this.prisma,
      config: this.config,
      limiters: this.limiters,
    };
  }

  /**
   * Create a context that also parses the incoming request headers.
   * @param request - The request containing authentication headers.
   */
  private createContextWithRequest(request: {
    headers: AuthHeaders;
  }): CoreContext {
    return {
      ...this.createBaseContext(),
      parsedRequest: parseRequest(request, this.config),
    };
  }

  /**
   * Instantiate AegisAuth with a Prisma client and an optional configuration.
   * The provided configuration is merged with defaults and validated.
   * @param prisma - The Prisma client instance.
   * @param userConfig - Optional partial configuration overrides.
   */
  constructor(prisma: PrismaClient, userConfig?: Partial<AegisAuthConfig>) {
    this.prisma = prisma;
    this.config = buildConfig(userConfig);

    // Initialize rate limiters only if enabled.
    if (this.config.rateLimiting.enabled && this.config.rateLimiting.redis) {
      const redis = this.config.rateLimiting.redis;
      const routes = [
        "login",
        "register",
        "verifyEmail",
        "initiatePasswordReset",
        "completePasswordReset",
        "initiateEmailChange",
        "completeEmailChange",
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
            prefix: `${this.config.rateLimiting.keyPrefix}:${route}:`,
          });
        }
      }
    }
  }

  /**
   * Get the current configuration.
   */
  getConfig() {
    return this.config;
  }

  /**
   * Ban a user by ID.
   */
  async banUser(input: Parameters<typeof banUserCore>[1]) {
    return banUserCore(this.createBaseContext(), input);
  }

  /**
   * Complete an email change by validating the provided token.
   */
  async completeEmailChange(
    request: { headers: AuthHeaders },
    input: Parameters<typeof completeEmailChangeCore>[1],
  ) {
    return completeEmailChangeCore(
      this.createContextWithRequest(request),
      input,
    );
  }

  /**
   * Complete a password reset using a verification token.
   */
  async completePasswordReset(
    request: { headers: AuthHeaders },
    input: Parameters<typeof completePasswordResetCore>[1],
  ) {
    return completePasswordResetCore(
      this.createContextWithRequest(request),
      input,
    );
  }

  /**
   * Create a new session for a given user.
   */
  async createSession(
    request: { headers: AuthHeaders },
    input: Parameters<typeof createSessionCore>[1],
  ) {
    return createSessionCore(this.createContextWithRequest(request), input);
  }

  /**
   * Create a verification record for a user.
   */
  async createVerification(
    input: Parameters<typeof createVerificationCore>[1],
  ) {
    return createVerificationCore(this.createBaseContext(), input);
  }

  /**
   * Initiate an email change process.
   */
  async initiateEmailChange(
    request: { headers: AuthHeaders },
    input: Parameters<typeof initiateEmailChangeCore>[1],
  ) {
    return initiateEmailChangeCore(
      this.createContextWithRequest(request),
      input,
    );
  }

  /**
   * Initiate a password reset process.
   */
  async initiatePasswordReset(
    request: { headers: AuthHeaders },
    input: Parameters<typeof initiatePasswordResetCore>[1],
  ) {
    return initiatePasswordResetCore(
      this.createContextWithRequest(request),
      input,
    );
  }

  /**
   * Log in a user with provided credentials.
   */
  async loginUser(
    request: { headers: AuthHeaders },
    input: Parameters<typeof loginUserCore>[1],
  ) {
    return loginUserCore(this.createContextWithRequest(request), input);
  }

  /**
   * Log out the current session.
   */
  async logoutUser(input: Parameters<typeof logoutUserCore>[1]) {
    return logoutUserCore(this.createBaseContext(), input);
  }

  /**
   * Register a new user.
   */
  async registerUser(
    request: { headers: AuthHeaders },
    input: Parameters<typeof registerUserCore>[1],
  ) {
    return registerUserCore(this.createContextWithRequest(request), input);
  }

  /**
   * Revoke all active sessions for a user.
   */
  async revokeAllSessionsForUser(
    input: Parameters<typeof revokeAllSessionsForUserCore>[1],
  ) {
    return revokeAllSessionsForUserCore(this.createBaseContext(), input);
  }

  /**
   * Revoke a specific session.
   */
  async revokeSession(input: Parameters<typeof revokeSessionCore>[1]) {
    return revokeSessionCore(this.createBaseContext(), input);
  }

  /**
   * Unban a user by ID.
   */
  async unbanUser(input: Parameters<typeof unbanUserCore>[1]) {
    return unbanUserCore(this.createBaseContext(), input);
  }

  /**
   * Update a user's roles.
   */
  async updateUserRoles(input: Parameters<typeof updateUserRolesCore>[1]) {
    return updateUserRolesCore(this.createBaseContext(), input);
  }

  /**
   * Mark a verification token as used.
   */
  async useVerificationToken(
    input: Parameters<typeof useVerificationTokenCore>[1],
  ) {
    return useVerificationTokenCore(this.createBaseContext(), input);
  }

  /**
   * Validate and (if needed) rotate the current session.
   */
  async validateAndRotateSession(
    request: { headers: AuthHeaders },
    input: Parameters<typeof validateAndRotateSessionCore>[1],
  ) {
    return validateAndRotateSessionCore(
      this.createContextWithRequest(request),
      input,
    );
  }

  /**
   * Verify a user's email using a token.
   */
  async verifyEmail(
    request: { headers: AuthHeaders },
    input: Parameters<typeof verifyEmailCore>[1],
  ) {
    return verifyEmailCore(this.createContextWithRequest(request), input);
  }
}
