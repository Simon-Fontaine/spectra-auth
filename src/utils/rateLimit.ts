import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";

/**
 * If these env vars are missing, throw an error at load time.
 */
if (!process.env.KV_REST_API_URL || !process.env.KV_REST_API_TOKEN) {
  throw new Error(
    "Redis connection details are missing in environment variables",
  );
}

const redis = new Redis({
  url: process.env.KV_REST_API_URL,
  token: process.env.KV_REST_API_TOKEN,
});

// 10 attempts per 15 minutes (per IP)
const ipRatelimit = new Ratelimit({
  redis,
  limiter: Ratelimit.fixedWindow(10, "900 s"),
  prefix: "login-ip",
});

/**
 * Throttle login attempts by IP address.
 */
export async function limitIPAttempts(ip: string) {
  const limit = await ipRatelimit.limit(ip);
  return {
    success: limit.success,
    remaining: limit.remaining,
    limit: limit.limit,
    reset: limit.reset,
  };
}
