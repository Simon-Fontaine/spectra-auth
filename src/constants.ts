/**
 * All error codes used across the authentication system
 */
export const ErrorCode = {
  // General errors
  GENERAL_ERROR: "GENERAL_ERROR",
  CONFIG_ERROR: "CONFIG_ERROR",
  SERVER_ERROR: "SERVER_ERROR",

  // Authentication errors
  AUTH_INVALID_CREDENTIALS: "AUTH_INVALID_CREDENTIALS",
  AUTH_EMAIL_NOT_VERIFIED: "AUTH_EMAIL_NOT_VERIFIED",
  AUTH_USER_BANNED: "AUTH_USER_BANNED",
  AUTH_USER_LOCKED: "AUTH_USER_LOCKED",
  AUTH_NOT_AUTHENTICATED: "AUTH_NOT_AUTHENTICATED",

  // Session errors
  SESSION_INVALID: "SESSION_INVALID",
  SESSION_EXPIRED: "SESSION_EXPIRED",
  SESSION_REVOKED: "SESSION_REVOKED",
  SESSION_FINGERPRINT_MISMATCH: "SESSION_FINGERPRINT_MISMATCH",
  SESSION_TOKEN_ERROR: "SESSION_TOKEN_ERROR",

  // Rate limiting
  RATE_LIMIT_EXCEEDED: "RATE_LIMIT_EXCEEDED",
  RATE_LIMIT_CONFIG_ERROR: "RATE_LIMIT_CONFIG_ERROR",

  // Registration
  REGISTER_DISABLED: "REGISTER_DISABLED",
  REGISTER_INVALID_DATA: "REGISTER_INVALID_DATA",
  REGISTER_USERNAME_EXISTS: "REGISTER_USERNAME_EXISTS",
  REGISTER_EMAIL_EXISTS: "REGISTER_EMAIL_EXISTS",
  REGISTER_INVITATION_REQUIRED: "REGISTER_INVITATION_REQUIRED",
  REGISTER_INVITATION_EXPIRED: "REGISTER_INVITATION_EXPIRED",

  // Email verification
  EMAIL_VERIFICATION_INVALID: "EMAIL_VERIFICATION_INVALID",
  EMAIL_VERIFICATION_EXPIRED: "EMAIL_VERIFICATION_EXPIRED",
  EMAIL_VERIFICATION_USED: "EMAIL_VERIFICATION_USED",

  // Password
  PASSWORD_RESET_INVALID: "PASSWORD_RESET_INVALID",
  PASSWORD_RESET_EXPIRED: "PASSWORD_RESET_EXPIRED",
  PASSWORD_COMPLEXITY: "PASSWORD_COMPLEXITY",
  PASSWORD_PREVIOUSLY_USED: "PASSWORD_PREVIOUSLY_USED",

  // Email change
  EMAIL_CHANGE_INVALID: "EMAIL_CHANGE_INVALID",
  EMAIL_CHANGE_SAME_EMAIL: "EMAIL_CHANGE_SAME_EMAIL",
  EMAIL_CHANGE_IN_USE: "EMAIL_CHANGE_IN_USE",

  // Account deletion
  ACCOUNT_DELETION_INVALID: "ACCOUNT_DELETION_INVALID",
  ACCOUNT_DELETION_FAILED: "ACCOUNT_DELETION_FAILED",

  // CSRF
  CSRF_MISSING: "CSRF_MISSING",
  CSRF_INVALID: "CSRF_INVALID",

  // Verification
  VERIFICATION_INVALID: "VERIFICATION_INVALID",
  VERIFICATION_EXPIRED: "VERIFICATION_EXPIRED",
  VERIFICATION_TYPE_MISMATCH: "VERIFICATION_TYPE_MISMATCH",
  VERIFICATION_ALREADY_USED: "VERIFICATION_ALREADY_USED",

  // Security
  SECURITY_TOKEN_ERROR: "SECURITY_TOKEN_ERROR",
  SECURITY_HASH_ERROR: "SECURITY_HASH_ERROR",

  // Fingerprint
  FINGERPRINT_INSUFFICIENT_DATA: "FINGERPRINT_INSUFFICIENT_DATA",
  FINGERPRINT_GENERATION_ERROR: "FINGERPRINT_GENERATION_ERROR",
  FINGERPRINT_MISSING: "FINGERPRINT_MISSING",
  FINGERPRINT_MISMATCH: "FINGERPRINT_MISMATCH",
  FINGERPRINT_VALIDATION_ERROR: "FINGERPRINT_VALIDATION_ERROR",
} as const;

export type ErrorCodeType = (typeof ErrorCode)[keyof typeof ErrorCode];

/**
 * Authentication endpoints that can be rate-limited
 */
export const Endpoints = {
  LOGIN: "login",
  REGISTER: "register",
  VERIFY_EMAIL: "verifyEmail",
  INITIATE_PASSWORD_RESET: "initiatePasswordReset",
  COMPLETE_PASSWORD_RESET: "completePasswordReset",
  INITIATE_EMAIL_CHANGE: "initiateEmailChange",
  COMPLETE_EMAIL_CHANGE: "completeEmailChange",
  INITIATE_ACCOUNT_DELETION: "initiateAccountDeletion",
  COMPLETE_ACCOUNT_DELETION: "completeAccountDeletion",
} as const;

export type EndpointName = (typeof Endpoints)[keyof typeof Endpoints];

/**
 * Verification types for different account operations
 */
export const VerificationAction = {
  VERIFY_EMAIL: "VERIFY_EMAIL",
  RESET_PASSWORD: "RESET_PASSWORD",
  CHANGE_EMAIL: "CHANGE_EMAIL",
  DELETE_ACCOUNT: "DELETE_ACCOUNT",
} as const;

export type VerificationActionType =
  (typeof VerificationAction)[keyof typeof VerificationAction];

/**
 * Common regex patterns used for validation
 */
export const RegexPatterns = {
  USERNAME: /^[a-z0-9_]{1,48}$/,
  DISPLAY_NAME: /^[a-zA-Z0-9_ ]{1,48}$/,
  EMAIL: /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/,
  PASSWORD_HAS_LOWERCASE: /[a-z]/,
  PASSWORD_HAS_UPPERCASE: /[A-Z]/,
  PASSWORD_HAS_NUMBER: /\d/,
  PASSWORD_HAS_SYMBOL: /[\W_]/,
  UUID: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,

  // IP address patterns
  IPV4_PRIVATE: [
    /^0\./, // Current network
    /^10\./, // Class A private network
    /^127\./, // Loopback
    /^169\.254\./, // Link local
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./, // Class B private network
    /^192\.168\./, // Class C private network
  ],
  IPV6_PRIVATE: [
    /^::1$/, // Loopback
    /^f[cd]/, // Unique local address
    /^fe80:/, // Link-local address
  ],
};

/**
 * Security-related constants
 */
export const Security = {
  DEFAULT_TOKEN_LENGTH: 32,
  DEFAULT_SESSION_TOKEN_LENGTH: 64,
  MINIMUM_PASSWORD_LENGTH: 8,
  RECOMMENDED_PASSWORD_LENGTH: 12,
  DEFAULT_HASH_ITERATIONS: 16384,
  DEFAULT_KEY_LENGTH: 64,
  MIN_ENTROPY_BITS: 72, // Recommended minimum entropy for secure passwords

  COOKIE_SAME_SITE_OPTIONS: ["strict", "lax", "none"] as const,
  COOKIE_PRIORITY_OPTIONS: ["low", "medium", "high"] as const,
};

/**
 * Time-related constants in milliseconds
 */
export const Time = {
  SECOND: 1000,
  MINUTE: 60 * 1000,
  HOUR: 60 * 60 * 1000,
  DAY: 24 * 60 * 60 * 1000,
  WEEK: 7 * 24 * 60 * 60 * 1000,
  MONTH: 30 * 24 * 60 * 60 * 1000,
  YEAR: 365 * 24 * 60 * 60 * 1000,

  // Common timeout values
  DEFAULT_SESSION_LIFETIME: 7 * 24 * 60 * 60 * 1000, // 7 days
  DEFAULT_SESSION_IDLE_TIMEOUT: 2 * 60 * 60 * 1000, // 2 hours
  DEFAULT_SESSION_REFRESH_INTERVAL: 60 * 60 * 1000, // 1 hour
  DEFAULT_VERIFICATION_EXPIRY: 24 * 60 * 60 * 1000, // 24 hours
  DEFAULT_LOCKOUT_DURATION: 30 * 60 * 1000, // 30 minutes
};

/**
 * Environment detection
 */
export enum ExecutionEnvironment {
  SERVER = "server",
  EDGE = "edge",
  SERVERLESS = "serverless",
}

/**
 * Session state enumeration
 */
export enum SessionState {
  ACTIVE = "active",
  EXPIRED = "expired",
  REVOKED = "revoked",
  SUSPICIOUS = "suspicious",
}
