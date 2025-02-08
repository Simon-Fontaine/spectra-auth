import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import type { SpectraAuthConfig } from "../config";

export function createRouteLimiter({
  routeKey,
  config,
}: {
  routeKey:
    | "login"
    | "register"
    | "verifyEmail"
    | "forgotPassword"
    | "passwordReset";
  config: Required<SpectraAuthConfig>;
}): Ratelimit {
  const rateLimitConfig = config.rateLimiting[routeKey];

  return new Ratelimit({
    redis: new Redis({
      url: config.rateLimiting.kvRestApiUrl,
      token: config.rateLimiting.kvRestApiToken,
    }),
    limiter: Ratelimit.fixedWindow(
      rateLimitConfig.maxRequests,
      `${rateLimitConfig.windowSeconds} s`,
    ),
    prefix: `spectra-route:${routeKey}:`,
  });
}

export async function limitIpAttempts({
  ipAddress,
  rateLimiter,
}: { ipAddress: string; rateLimiter: Ratelimit }): Promise<{
  success: boolean;
  remaining: number;
  limit: number;
  reset: number;
}> {
  const limit = await rateLimiter.limit(ipAddress);
  return {
    success: limit.success,
    remaining: limit.remaining,
    limit: limit.limit,
    reset: limit.reset,
  };
}
