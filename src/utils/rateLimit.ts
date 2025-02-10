import type { Ratelimit } from "@upstash/ratelimit";

export async function limitIpAttempts({
  ipAddress,
  limiter,
}: { ipAddress: string; limiter: Ratelimit }): Promise<{
  success: boolean;
  remaining: number;
  limit: number;
  reset: number;
}> {
  const limit = await limiter.limit(ipAddress);
  return {
    success: limit.success,
    remaining: limit.remaining,
    limit: limit.limit,
    reset: limit.reset,
  };
}
