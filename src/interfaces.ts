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
  isRevoked: boolean;
  expiresAt: Date;
}

/**
 * Minimal verification fields that the library references for verifying tokens.
 */
export interface AuthVerification {
  id: string;
  userId: string;
  token: string;
  type: string;
  expiresAt: Date;
  usedAt: Date | null;
}
