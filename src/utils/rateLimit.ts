import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { DEFAULT_CONFIG } from "../config/defaults";
import type { SpectraAuthConfig } from "../types";

/**
 * Create a rate limiter based on the provided strategy.
 */
export function createRateLimiter(
  config: SpectraAuthConfig,
  prefix: string,
): Ratelimit {
  const {
    kvRestApiUrl,
    kvRestApiToken,
    rateLimitingStrategy,
    attempts = DEFAULT_CONFIG.attempts,
    windowSeconds = DEFAULT_CONFIG.windowSeconds,
  } = config;

  const redis = new Redis({
    url: kvRestApiUrl,
    token: kvRestApiToken,
  });

  switch (rateLimitingStrategy) {
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
 * Throttle login attempts by IP address.
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
