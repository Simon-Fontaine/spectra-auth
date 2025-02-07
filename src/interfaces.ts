/**
 * Minimal user fields that the library needs for login, lockouts, etc.
 */
export interface AuthUser {
  id: string;
  email: string;
  password: string;
  isEmailVerified: boolean;
  isBanned: boolean;
  failedLoginAttempts: number;
  lockedUntil: Date | null;
}

/**
 * Minimal session fields that the library needs for validation, revocation, etc.
 */
export interface AuthSession {
  id: string;
  userId: string;
  tokenPrefix: string | null;
  tokenHash: string | null;
  csrfSecret: string | null;
  isRevoked: boolean;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
  // Optional device info
  ipAddress: string | null;
  location: string | null;
  country: string | null;
  device: string | null;
  browser: string | null;
  userAgent: string | null;
}

/**
 * Cleaned-up session fields that are safe to return in API responses.
 */
export interface CleanAuthSession {
  id: string;
  userId: string;
  isRevoked: boolean;
  expiresAt: Date;
  createdAt: Date;
  updatedAt: Date;
  rawToken: string | null;
  // Optional device info
  ipAddress: string | null;
  location: string | null;
  country: string | null;
  device: string | null;
  browser: string | null;
  userAgent: string | null;
}

/**
 * Minimal verification fields that the library references for verifying tokens.
 */
export interface AuthVerification {
  id: string;
  userId: string;
  token: string;
  type: string;
  metadata?: Record<string, unknown>;
  expiresAt: Date;
  usedAt: Date | null;
  createdAt: Date;
  updatedAt: Date;
}
