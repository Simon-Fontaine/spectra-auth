export interface SpectraAuthResult {
  error: boolean;
  status: number;
  message: string;
  code?: string;
  data?: Record<string, unknown>;
}

export interface LoggerInterface {
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
  securityEvent: (eventType: string, meta: Record<string, unknown>) => void;
}

export interface RouteRateLimit {
  attempts: number;
  windowSeconds: number;
}

export interface SensitiveRoutesRateLimitConfig {
  login?: RouteRateLimit;
  register?: RouteRateLimit;
  passwordReset?: RouteRateLimit;
}

export interface SessionConfig {
  maxAgeSec: number;
  updateAgeSec: number;
  maxSessionsPerUser: number;
}

export interface AccountLockConfig {
  threshold: number;
  durationMs: number;
}

export interface RateLimitConfig {
  disable?: boolean;
  kvRestApiUrl?: string;
  kvRestApiToken?: string;
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

export type VerificationType =
  | "EMAIL_VERIFICATION"
  | "PASSWORD_RESET"
  | "ACCOUNT_DELETION"
  | "EMAIL_CHANGE";

export type RateLimitingStrategy =
  | "fixedWindow"
  | "slidingWindow"
  | "tokenBucket";

export type TypedArray =
  | Uint8Array
  | Int8Array
  | Uint16Array
  | Int16Array
  | Uint32Array
  | Int32Array
  | Float32Array
  | Float64Array
  | BigInt64Array
  | BigUint64Array;

export type SHAFamily = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";
export type EncodingFormat =
  | "hex"
  | "base64"
  | "base64url"
  | "base64urlnopad"
  | "none";
export type ECDSACurve = "P-256" | "P-384" | "P-521";
export type ExportKeyFormat = "jwk" | "spki" | "pkcs8" | "raw";
