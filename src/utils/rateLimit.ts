import type { Ratelimit } from "@upstash/ratelimit";

export async function limitIpAddress(ip: string, limiter: Ratelimit) {
  const limit = await limiter.limit(ip);
  return { ...limit };
}
