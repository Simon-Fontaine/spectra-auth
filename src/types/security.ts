/**
 * Array buffer or typed array for cryptographic operations
 */
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

/**
 * Supported hash algorithms
 */
export type SHAFamily = "SHA-1" | "SHA-256" | "SHA-384" | "SHA-512";

/**
 * Supported encoding formats for hash outputs
 */
export type EncodingFormat =
  | "hex"
  | "base64"
  | "base64url"
  | "base64urlnopad"
  | "none";

/**
 * Branded type for session tokens to prevent accidental misuse
 */
export type SessionToken = string & { readonly __type: unique symbol };

/**
 * Branded type for CSRF tokens to prevent accidental misuse
 */
export type CsrfToken = string & { readonly __type: unique symbol };

/**
 * Branded type for verification tokens to prevent accidental misuse
 */
export type VerificationToken = string & { readonly __type: unique symbol };

/**
 * Password hash format string ("salt:derivedKey")
 */
export type PasswordHash = string & { readonly __type: unique symbol };

/**
 * Helper functions to create branded types
 */
export function createSessionToken(raw: string): SessionToken {
  return raw as SessionToken;
}

export function createCsrfToken(raw: string): CsrfToken {
  return raw as CsrfToken;
}

export function createVerificationToken(raw: string): VerificationToken {
  return raw as VerificationToken;
}

export function createPasswordHash(raw: string): PasswordHash {
  return raw as PasswordHash;
}
