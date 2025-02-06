/**
 * Standard result returned by most library functions.
 */
export interface SpectraAuthResult {
  /**
   * Indicates if an error occurred.
   */
  error: boolean;

  /**
   * Numeric HTTP-style status code (e.g., 200, 400, 401, 429, etc.).
   */
  status: number;

  /**
   * Human-readable message describing the result.
   */
  message: string;

  /**
   * Optional internal code for debugging or logging
   */
  code?: string;

  /**
   * Optional data returned on success, such as a token, userId, or other fields.
   */
  data?: Record<string, unknown>;
}

export interface LoggerInterface {
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
}

export interface SpectraAuthConfig {
  // Session
  sessionMaxAgeSec?: number;
  sessionUpdateAgeSec?: number;

  // Account Lockouts
  accountLockThreshold?: number;
  accountLockDurationMs?: number;

  // Rate-limiting
  rateLimitingStrategy?: RateLimitingStrategy;
  attempts?: number;
  windowSeconds?: number;

  // CSRF
  enableCSRF?: boolean;
  csrfSecret?: string; // used to generate & verify CSRF tokens

  // Logging
  logger?: LoggerInterface;
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
