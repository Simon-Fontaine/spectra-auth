import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import type { RateLimitingStrategy } from "../types";

const redis = new Redis({
  url: process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
});

/**
 * Create a rate limiter based on the provided strategy.
 */
export function createRateLimiter(
  strategy: RateLimitingStrategy,
  attempts: number,
  windowSeconds: number,
): Ratelimit {
  switch (strategy) {
    case "slidingWindow":
      return new Ratelimit({
        redis,
        limiter: Ratelimit.slidingWindow(attempts, `${windowSeconds} s`),
        prefix: "login-ip",
      });
    case "tokenBucket":
      return new Ratelimit({
        redis,
        limiter: Ratelimit.tokenBucket(
          attempts,
          `${windowSeconds} s`,
          attempts,
        ),
        prefix: "login-ip",
      });
    default:
      return new Ratelimit({
        redis,
        limiter: Ratelimit.fixedWindow(attempts, `${windowSeconds} s`),
        prefix: "login-ip",
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
