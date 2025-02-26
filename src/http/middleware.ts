import { ErrorCode } from "../constants";
import { verifyCsrfToken } from "../security/tokens";
import type { AegisContext, AegisResponse } from "../types";
import { fail } from "../utils/response";

/**
 * Middleware function type definition
 */
export type Middleware = (
  ctx: AegisContext,
  next: () => Promise<AegisResponse<unknown>>,
) => Promise<AegisResponse<unknown>>;

/**
 * Applies a series of middleware functions to a request handler
 *
 * @param ctx - Authentication context
 * @param middlewares - Array of middleware functions
 * @param handler - Final request handler
 * @returns Result of the handler after middleware processing
 */
export function applyMiddleware(
  ctx: AegisContext,
  middlewares: Middleware[],
  handler: () => Promise<AegisResponse<unknown>>,
): Promise<AegisResponse<unknown>> {
  // Execute middlewares in sequence
  const executeMiddleware = async (
    index: number,
  ): Promise<AegisResponse<unknown>> => {
    if (index >= middlewares.length) {
      return handler();
    }

    return middlewares[index](ctx, () => executeMiddleware(index + 1));
  };

  return executeMiddleware(0);
}

/**
 * Middleware that requires the user to be authenticated
 *
 * @param ctx - Authentication context
 * @param next - Next middleware or handler
 * @returns Result of next or authentication error
 */
export const requireAuth: Middleware = async (ctx, next) => {
  if (!ctx.auth.isAuthenticated || !ctx.auth.user) {
    return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Authentication required");
  }

  return next();
};

/**
 * Middleware that requires specific permissions
 *
 * @param requiredPermissions - Array of permissions required
 * @returns Middleware function
 */
export const requirePermissions = (
  requiredPermissions: string[],
): Middleware => {
  return async (ctx, next) => {
    // Check authentication first
    if (!ctx.auth.isAuthenticated || !ctx.auth.user) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Authentication required");
    }

    // Check if user has all required permissions
    const userPermissions = ctx.auth.user.permissions || [];

    const hasAllPermissions = requiredPermissions.every((permission) =>
      userPermissions.includes(permission),
    );

    if (!hasAllPermissions) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Insufficient permissions");
    }

    return next();
  };
};

/**
 * Middleware that requires specific roles
 *
 * @param requiredRoles - Array of roles required
 * @returns Middleware function
 */
export const requireRoles = (requiredRoles: string[]): Middleware => {
  return async (ctx, next) => {
    // Check authentication first
    if (!ctx.auth.isAuthenticated || !ctx.auth.user) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Authentication required");
    }

    // Check if user has any of the required roles
    const userRoles = ctx.auth.user.roles || [];

    const hasAnyRole = requiredRoles.some((role) => userRoles.includes(role));

    if (!hasAnyRole) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Insufficient role");
    }

    return next();
  };
};

/**
 * Middleware that enforces CSRF protection
 *
 * @param ctx - Authentication context
 * @param next - Next middleware or handler
 * @returns Result of next or CSRF error
 */
export const csrfProtection: Middleware = async (ctx, next) => {
  const { config, req, auth } = ctx;

  // Skip if CSRF is disabled
  if (!config.csrf.enabled) {
    return next();
  }

  // Skip for unauthenticated users or non-mutating methods
  if (!auth.isAuthenticated || !auth.session) {
    return next();
  }

  // Get CSRF token from request
  if (!req.csrfToken) {
    return fail(ErrorCode.CSRF_MISSING, "CSRF token is required");
  }

  // Verify CSRF token
  const verificationResult = await verifyCsrfToken(
    req.csrfToken,
    auth.session.csrfTokenHash,
    config,
  );

  if (!verificationResult.success || !verificationResult.data) {
    return fail(ErrorCode.CSRF_INVALID, "Invalid CSRF token");
  }

  return next();
};
