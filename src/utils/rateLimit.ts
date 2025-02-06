import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import type { RateLimitingStrategy, SpectraAuthConfig } from "../types";

/**
 * Creates a rate limiter based on the configured strategy.
 *
 * - Supports multiple strategies such as sliding window, token bucket, and fixed window.
 * - Utilizes Upstash Redis for distributed rate limiting.
 *
 * @param config - The SpectraAuth configuration object.
 * @param attempts - The number of attempts allowed within the window.
 * @param windowSeconds - The duration of the rate-limiting window in seconds.
 * @param strategy - The rate-limiting strategy to use.
 * @param prefix - A prefix to distinguish rate limiters (e.g., by route or action).
 * @returns A configured Ratelimit instance.
 */
export function createRateLimiter(
  config: SpectraAuthConfig,
  attempts: number,
  windowSeconds: number,
  strategy: RateLimitingStrategy,
  prefix: string,
): Ratelimit {
  const { kvRestApiUrl, kvRestApiToken } = config.rateLimit;

  // Validate configuration values
  if (attempts <= 0 || windowSeconds <= 0) {
    throw new Error("Rate limiting configuration must have positive values.");
  }

  const redis = new Redis({
    url: kvRestApiUrl,
    token: kvRestApiToken,
  });

  switch (strategy) {
    case "slidingWindow":
      return new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(attempts, `${windowSeconds} s`),
        prefix,
      });
    case "tokenBucket":
      return new Ratelimit({
        redis,
        limiter: Ratelimit.tokenBucket(
          attempts,
          `${windowSeconds} s`,
          attempts,
        ),
        prefix,
      });
    default:
      return new Ratelimit({
        redis,
        limiter: Ratelimit.fixedWindow(attempts, `${windowSeconds} s`),
        prefix,
      });
  }
}

/**
 * Creates a route-specific rate limiter.
 *
 * - If no route-specific override exists, returns `null`.
 * - Uses fixed window strategy by default for route rate limiters.
 *
 * @param routeKey - The key identifying the route-specific rate limiter.
 * @param config - The SpectraAuth configuration object.
 * @returns A configured Ratelimit instance or `null` if no override is specified.
 */
export function createRouteRateLimiter(
  routeKey: keyof NonNullable<SpectraAuthConfig["routeRateLimit"]>,
  config: SpectraAuthConfig,
): Ratelimit | null {
  const override = config.routeRateLimit?.[routeKey];

  // If no override is specified for the route, return null
  if (!override) return null;

  return createRateLimiter(
    config,
    override.attempts,
    override.windowSeconds,
    "fixedWindow",
    `spectra-route:${String(routeKey)}`,
  );
}

/**
 * Limits the number of attempts from a given IP address.
 *
 * - Utilizes the provided rate limiter to throttle requests.
 *
 * @param ip - The IP address of the client.
 * @param rateLimiter - The configured Ratelimit instance.
 * @returns An object containing rate-limiting status and remaining attempts.
 */
export async function limitIPAttempts(ip: string, rateLimiter: Ratelimit) {
  const limit = await rateLimiter.limit(ip);
  return {
    success: limit.success,
    remaining: limit.remaining,
    limit: limit.limit,
    reset: limit.reset,
  };
}
