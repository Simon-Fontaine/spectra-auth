import type { Ratelimit } from "@upstash/ratelimit";
import type { AegisAuthConfig, AegisResponse, EndpointName } from "../types";
import { fail } from "./response";

/**
 * Applies rate limiting to an IP address
 *
 * @param ip - The IP address to limit
 * @param limiter - The Upstash Ratelimit instance
 * @returns A response object containing limit results
 */
export async function limitIpAddress(ip: string, limiter: Ratelimit) {
  const limit = await limiter.limit(ip);
  return { ...limit };
}

/**
 * Higher-order function that handles rate limiting logic for any operation
 *
 * @param ctx - Authentication context
 * @param endpointName - Name of the endpoint for rate limit configuration
 * @param operation - The async operation to execute if limit is not exceeded
 * @returns The result of the operation or rate limit error
 */
export async function withRateLimit<T>(
  ctx: {
    config: AegisAuthConfig;
    endpoints: Record<string, Ratelimit>;
    req: { ipAddress?: string };
  },
  endpointName: EndpointName,
  operation: () => Promise<AegisResponse<T>>,
): Promise<AegisResponse<T>> {
  const { config, endpoints, req } = ctx;
  const { ipAddress } = req;

  // Skip rate limiting if disabled or no IP address
  if (
    !config.rateLimit.enabled ||
    !config.rateLimit.endpoints[endpointName]?.enabled ||
    !ipAddress
  ) {
    return operation();
  }

  const limiter = endpoints[endpointName];
  if (!limiter) {
    config.logger?.error(`Missing rate-limit endpoint for ${endpointName}`, {
      ipAddress,
    });
    return fail(
      "RATE_LIMIT_ERROR",
      "Server misconfiguration. Please try again later.",
    );
  }

  // Apply rate limiting
  const limit = await limitIpAddress(ipAddress, limiter);
  if (!limit.success) {
    config.logger?.warn(`Rate limit exceeded for ${endpointName}`, {
      ipAddress,
      remainingRequests: limit.remaining,
      limit: limit.limit,
      reset: new Date(limit.reset).toISOString(),
    });

    return fail(
      `${endpointName.toUpperCase()}_RATE_LIMIT_EXCEEDED`,
      "Too many requests. Please try again later.",
    );
  }

  // Execute the operation if rate limit check passes
  return operation();
}

/**
 * Create a custom rate limiter key that combines IP and user ID
 * This prevents multiple users behind the same IP (or the same user on multiple IPs)
 * from exceeding limits independently
 *
 * @param ip - IP address
 * @param userId - User ID (optional)
 * @returns A combined key for rate limiting
 */
export function createRateLimitKey(ip: string, userId?: string): string {
  if (userId) {
    return `${ip}:${userId}`;
  }
  return ip;
}
