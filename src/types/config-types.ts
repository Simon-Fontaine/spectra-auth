import type { LoggerInterface } from "./logger-interface";
import type {
  RateLimitConfig,
  SensitiveRoutesRateLimitConfig,
} from "./rate-limiting-types";

export interface SessionConfig {
  maxAgeSec: number;
  updateAgeSec: number;
  maxSessionsPerUser: number;
  cookieSecure: boolean;
  cookieSameSite: "strict" | "lax" | "none";
}

export interface AccountLockConfig {
  threshold: number;
  durationMs: number;
}

export interface CSRFConfig {
  enabled: boolean;
  secret: string;
}

export interface SpectraAuthConfig {
  session: SessionConfig;
  accountLock: AccountLockConfig;
  rateLimit: RateLimitConfig;
  routeRateLimit: SensitiveRoutesRateLimitConfig;
  csrf: CSRFConfig;
  passwordPepper: string;
  logger: LoggerInterface;
}
