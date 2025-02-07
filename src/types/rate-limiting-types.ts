export interface RouteRateLimit {
  attempts: number;
  windowSeconds: number;
}

export interface SensitiveRoutesRateLimitConfig {
  login?: RouteRateLimit;
  register?: RouteRateLimit;
  passwordReset?: RouteRateLimit;
}

export type RateLimitingStrategy =
  | "fixedWindow"
  | "slidingWindow"
  | "tokenBucket";
