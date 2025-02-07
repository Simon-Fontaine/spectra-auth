export interface RouteRateLimit {
  attempts: number;
  windowSeconds: number;
}

export interface SensitiveRoutesRateLimitConfig {
  login?: RouteRateLimit;
  register?: RouteRateLimit;
  passwordReset?: RouteRateLimit;
}

export interface RateLimitConfig {
  disable?: boolean;
  kvRestApiUrl?: string;
  kvRestApiToken?: string;
}

export type RateLimitingStrategy =
  | "fixedWindow"
  | "slidingWindow"
  | "tokenBucket";
