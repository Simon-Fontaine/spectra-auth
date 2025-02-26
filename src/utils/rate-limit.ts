import type { Ratelimit } from "@upstash/ratelimit";
import { type EndpointName, ErrorCode } from "../constants";
import type { AegisContext, AegisResponse } from "../types";
import { fail } from "./response";

/**
 * Applies rate limiting to a request by IP address
 *
 * @param ip - IP address to rate limit
 * @param limiter - Rate limiter instance
 * @returns Rate limiting result
 */
export async function limitByIP(
  ip: string,
  limiter: Ratelimit,
): Promise<{
  success: boolean;
  limit: number;
  remaining: number;
  reset: number;
}> {
  const limit = await limiter.limit(ip);
  return { ...limit };
}

/**
 * Creates a rate limit key that can include user ID
 *
 * @param ip - IP address
 * @param userId - Optional user ID
 * @returns Combined rate limit key
 */
export function createRateLimitKey(ip: string, userId?: string): string {
  if (userId) {
    return `${ip}:${userId}`;
  }
  return ip;
}

/**
 * Higher-order function to apply rate limiting to an operation
 *
 * @param ctx - Authentication context
 * @param endpointName - Name of the endpoint for rate limiting
 * @param operation - Operation to execute if rate limit passes
 * @returns Result of operation or rate limit error
 */
export async function withRateLimit<T>(
  ctx: AegisContext,
  endpointName: EndpointName,
  operation: () => Promise<AegisResponse<T>>,
): Promise<AegisResponse<T>> {
  const { config, endpoints, req, auth } = ctx;

  // Skip rate limiting if disabled or no IP address
  if (
    !config.rateLimit.enabled ||
    !config.rateLimit.endpoints[endpointName]?.enabled ||
    !req.ipAddress
  ) {
    return operation();
  }

  // Get rate limiter for this endpoint
  const limiter = endpoints[endpointName];
  if (!limiter) {
    ctx.config.logger?.error(
      `Missing rate limiter for endpoint: ${endpointName}`,
      {
        ipAddress: req.ipAddress,
      },
    );

    return fail(
      ErrorCode.RATE_LIMIT_CONFIG_ERROR,
      "Server configuration error. Please try again later.",
    );
  }

  // Create rate limit key (include user ID if authenticated)
  const limitKey =
    auth.isAuthenticated && auth.user
      ? createRateLimitKey(req.ipAddress, auth.user.id)
      : req.ipAddress;

  // Apply rate limiting
  const limit = await limitByIP(limitKey, limiter);

  if (!limit.success) {
    ctx.config.logger?.warn(`Rate limit exceeded for ${endpointName}`, {
      ipAddress: req.ipAddress,
      userId: auth.user?.id,
      remaining: limit.remaining,
      limit: limit.limit,
      reset: new Date(limit.reset).toISOString(),
    });

    return fail(
      ErrorCode.RATE_LIMIT_EXCEEDED,
      "Too many requests. Please try again later.",
      {
        retryAfter: Math.ceil((limit.reset - Date.now()) / 1000),
      },
    );
  }

  // Execute the operation if rate limit check passes
  return operation();
}
