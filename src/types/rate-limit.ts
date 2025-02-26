import type { Ratelimit } from "@upstash/ratelimit";
import type { EndpointName } from "../constants";

/**
 * Rate limiting result
 */
export interface RateLimitResult {
  success: boolean;
  limit: number;
  remaining: number;
  reset: number;
}

/**
 * Rate limit check function
 */
export type RateLimitCheck = (key: string) => Promise<RateLimitResult>;

/**
 * Rate limiting service
 */
export interface RateLimitService {
  checkLimit: RateLimitCheck;
  getLimit: (key: string) => Promise<number>;
  getReset: (key: string) => Promise<Date>;
}

/**
 * Collection of rate limiters by endpoint
 */
export type RateLimiters = Partial<Record<EndpointName, Ratelimit>>;
