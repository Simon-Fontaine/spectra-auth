import type { LoggerInterface } from "./logger-interface";

export interface SpectraAuthConfig {
  logger?: LoggerInterface;
  securityEventLogger?: LoggerInterface;
  session?: SessionConfig;
  rateLimit?: RateLimitConfig;
  accountLock?: AccountLockConfig;
  passwordPepper?: string;
  csrf?: CSRFConfig;
}

export interface SessionConfig {
  cookieName: string;
  maxAgeSec: number;
  tokenLengthBytes: number;
  tokenPrefixLengthBytes: number;
  tokenSecret: string;
  csrfSecret: string;
  cookieSecure: boolean;
  cookieSameSite: "lax" | "strict" | "none";
  cookieHttpOnly: boolean;
  maxSessionsPerUser?: number;
}

export interface RateLimitConfig {
  disable: boolean;
  kvRestApiUrl?: string;
  kvRestApiToken?: string;
  loginRoute?: RouteRateLimitConfig;
  registerRoute?: RouteRateLimitConfig;
  passwordResetRoute?: RouteRateLimitConfig;
}

export interface RouteRateLimitConfig {
  enabled: boolean;
  attempts: number;
  windowSeconds: number;
}

export interface AccountLockConfig {
  enabled: boolean;
  threshold: number;
  durationMs: number;
}

export interface CSRFConfig {
  enabled: boolean;
  cookieName: string;
  headerName: string;
  formFieldName: string;
  tokenLengthBytes: number;
  cookieSecure: boolean;
  cookieHttpOnly: boolean;
  cookieSameSite: "Strict" | "Lax" | "None";
  maxAgeSec: number;
}
