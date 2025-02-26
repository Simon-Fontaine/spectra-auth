/**
 * AegisAuth - A secure authentication system for modern web applications
 *
 * @packageDocumentation
 */

import type { PrismaClient } from "@prisma/client";
import { Ratelimit } from "@upstash/ratelimit";
import { buildConfig } from "./config";
import { Endpoints, ErrorCode, SessionState } from "./constants";
import * as accountModule from "./core/account";
import * as authModule from "./core/auth";
import {
  applyMiddleware,
  csrfProtection,
  formatResponse,
  getClearAuthCookies,
  processRequest,
  requireAuth,
  requirePermissions,
  requireRoles,
} from "./http";
import type {
  AegisAuthConfig,
  AegisContext,
  AegisResponse,
  AuthenticatedUser,
  Endpoints as EndpointsType,
} from "./types";

/**
 * Main AegisAuth class for managing authentication
 */
export class AegisAuth {
  private readonly config: AegisAuthConfig;
  private readonly prisma: PrismaClient;
  private readonly endpoints: EndpointsType = {};

  /**
   * Create a new instance of AegisAuth
   *
   * @param prisma - Prisma client instance
   * @param userConfig - Authentication configuration options
   */
  constructor(prisma: PrismaClient, userConfig?: Partial<AegisAuthConfig>) {
    this.prisma = prisma;

    // Build and validate configuration
    const configResult = buildConfig(userConfig || {});
    if (!configResult.success) {
      throw new Error(
        `Failed to initialize AegisAuth: ${configResult.error.message}`,
      );
    }

    this.config = configResult.data;
    this.initializeRateLimiters();
  }

  /**
   * Initialize rate limiters for configured endpoints
   */
  private initializeRateLimiters(): void {
    const { rateLimit } = this.config;
    if (!rateLimit.enabled || !rateLimit.redis) {
      return;
    }

    try {
      // Create rate limiters for each enabled endpoint
      for (const [endpoint, config] of Object.entries(rateLimit.endpoints)) {
        if (config?.enabled) {
          this.endpoints[endpoint as keyof typeof Endpoints] = new Ratelimit({
            redis: rateLimit.redis,
            limiter: Ratelimit.slidingWindow(
              config.maxRequests,
              `${config.windowSeconds} s`,
            ),
            prefix: `${rateLimit.prefix}:${endpoint}`,
            analytics: true,
          });
        }
      }
    } catch (error) {
      this.config.logger?.error("Failed to initialize rate limiters", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  /**
   * Create an authentication context from request headers
   *
   * @param headers - HTTP request headers
   * @returns Authentication context or throws an error
   */
  async createContext(headers: Headers): Promise<AegisContext> {
    const result = await processRequest(
      this.prisma,
      this.config,
      this.endpoints,
      headers,
    );

    if (!result.success) {
      throw new Error(`Failed to create context: ${result.error.message}`);
    }

    return result.data;
  }

  /**
   * Get the current configuration
   *
   * @returns Authentication configuration
   */
  getConfig(): AegisAuthConfig {
    return { ...this.config };
  }

  /**
   * Register a new user
   *
   * @param headers - HTTP request headers
   * @param request - Registration request data
   * @param host - Optional host for cookie domain resolution
   * @returns Registration result
   */
  async register(
    headers: Headers,
    request: authModule.RegisterRequest,
  ): Promise<AegisResponse<authModule.RegisterResponse>> {
    const ctx = await this.createContext(headers);
    return authModule.register(ctx, request);
  }

  /**
   * Authenticate a user
   *
   * @param headers - HTTP request headers
   * @param request - Login request data
   * @param host - Optional host for cookie domain resolution
   * @returns Authentication result with session cookies
   */
  async login(
    headers: Headers,
    request: authModule.LoginRequest,
  ): Promise<AegisResponse<authModule.LoginResponse>> {
    const ctx = await this.createContext(headers);
    return authModule.login(ctx, request);
  }

  /**
   * Log out the current user
   *
   * @param headers - HTTP request headers
   * @param host - Optional host for cookie domain resolution
   * @returns Logout result with cookie clearing instructions
   */
  async logout(
    headers: Headers,
  ): Promise<
    AegisResponse<{ cookies: { sessionCookie: string; csrfCookie: string } }>
  > {
    const ctx = await this.createContext(headers);
    return authModule.logout(ctx);
  }

  /**
   * Log out all sessions for the current user
   *
   * @param headers - HTTP request headers
   * @param host - Optional host for cookie domain resolution
   * @returns Logout result with session count and cookie clearing instructions
   */
  async logoutAll(headers: Headers): Promise<
    AegisResponse<{
      cookies: { sessionCookie: string; csrfCookie: string };
      sessionsRevoked: number;
    }>
  > {
    const ctx = await this.createContext(headers);
    return authModule.logoutAll(ctx);
  }

  /**
   * Verify email address with verification token
   *
   * @param headers - HTTP request headers
   * @param token - Verification token
   * @returns Email verification result
   */
  async verifyEmail(
    headers: Headers,
    token: string,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.completeEmailVerification(ctx, token);
  }

  /**
   * Send email verification link
   *
   * @param headers - HTTP request headers
   * @returns Result of sending verification email
   */
  async sendVerificationEmail(
    headers: Headers,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.initiateEmailVerification(ctx);
  }

  /**
   * Initiate password reset
   *
   * @param headers - HTTP request headers
   * @param email - User email address
   * @returns Result of password reset request
   */
  async initiatePasswordReset(
    headers: Headers,
    email: string,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.initiatePasswordReset(ctx, email);
  }

  /**
   * Complete password reset with token
   *
   * @param headers - HTTP request headers
   * @param token - Reset token
   * @param password - New password
   * @returns Result of password reset
   */
  async completePasswordReset(
    headers: Headers,
    token: string,
    password: string,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.completePasswordReset(ctx, { token, password });
  }

  /**
   * Change password for authenticated user
   *
   * @param headers - HTTP request headers
   * @param currentPassword - Current password
   * @param newPassword - New password
   * @returns Result of password change
   */
  async changePassword(
    headers: Headers,
    currentPassword: string,
    newPassword: string,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.changePassword(ctx, { currentPassword, newPassword });
  }

  /**
   * Initiate email change
   *
   * @param headers - HTTP request headers
   * @param newEmail - New email address
   * @returns Result of email change request
   */
  async initiateEmailChange(
    headers: Headers,
    newEmail: string,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.initiateEmailChange(ctx, newEmail);
  }

  /**
   * Complete email change with verification token
   *
   * @param headers - HTTP request headers
   * @param token - Verification token
   * @returns Result of email change
   */
  async completeEmailChange(
    headers: Headers,
    token: string,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.completeEmailChange(ctx, token);
  }

  /**
   * Initiate account deletion
   *
   * @param headers - HTTP request headers
   * @returns Result of account deletion request
   */
  async initiateAccountDeletion(
    headers: Headers,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.initiateAccountDeletion(ctx);
  }

  /**
   * Complete account deletion with verification token
   *
   * @param headers - HTTP request headers
   * @param token - Verification token
   * @returns Result of account deletion
   */
  async completeAccountDeletion(
    headers: Headers,
    token: string,
  ): Promise<AegisResponse<boolean>> {
    const ctx = await this.createContext(headers);
    return accountModule.completeAccountDeletion(ctx, token);
  }

  /**
   * Get current authenticated user if available
   *
   * @param headers - HTTP request headers
   * @returns Current user or null if not authenticated
   */
  async getCurrentUser(headers: Headers): Promise<AuthenticatedUser | null> {
    const ctx = await this.createContext(headers);
    return ctx.auth.user || null;
  }

  /**
   * Check if user is authenticated
   *
   * @param headers - HTTP request headers
   * @returns True if authenticated
   */
  async isAuthenticated(headers: Headers): Promise<boolean> {
    const ctx = await this.createContext(headers);
    return ctx.auth.isAuthenticated;
  }

  /**
   * Apply middleware to a request handler
   *
   * @param ctx - Authentication context
   * @param middlewares - Array of middleware functions
   * @param handler - Request handler function
   * @returns Result of handler after middleware processing
   */
  applyMiddleware<T>(
    ctx: AegisContext,
    middlewares: Array<
      (
        ctx: AegisContext,
        next: () => Promise<AegisResponse<unknown>>,
      ) => Promise<AegisResponse<unknown>>
    >,
    handler: () => Promise<AegisResponse<T>>,
  ): Promise<AegisResponse<T>> {
    return applyMiddleware(ctx, middlewares, handler) as Promise<
      AegisResponse<T>
    >;
  }
}

// Export core authentication components
export { authModule as auth };
export { accountModule as account };

// Export middleware components
export { requireAuth, requirePermissions, requireRoles, csrfProtection };

// Export HTTP utilities
export { formatResponse, getClearAuthCookies };

// Export constants
export { ErrorCode, Endpoints, SessionState };

// Export types
export type { AegisAuthConfig, AegisContext, AegisResponse, AuthenticatedUser };

// Export individual authentication operations for advanced usage
export const { login, logout, register } = authModule;

export const {
  initiateEmailVerification,
  completeEmailVerification,
  initiatePasswordReset,
  completePasswordReset,
  changePassword,
  initiateEmailChange,
  completeEmailChange,
  initiateAccountDeletion,
  completeAccountDeletion,
} = accountModule;

// Default export
export default AegisAuth;
