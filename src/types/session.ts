import type { SessionState } from "../constants";
import type { SessionDevice, SessionLocation } from "./geo";
import type { CsrfToken, SessionToken } from "./security";

/**
 * Session metadata stored with each active session
 */
export interface SessionMetadata {
  location?: SessionLocation;
  device?: SessionDevice;
  fingerprint?: string;
  userAgent?: string;
  lastActive?: string;
  createdAt?: string;
  createdIp?: string;
  lastActiveIp?: string;
  rotations?: number;
  lastRotatedAt?: string;
  revocationReason?: string;
  revokedAt?: string;
  revocationIp?: string;
  [key: string]: unknown;
}

/**
 * Options for fingerprint generation and validation
 */
export interface FingerprintOptions {
  enabled: boolean;
  includeIp: boolean;
  strictValidation: boolean;
  maxDevicesPerUser?: number;
}

/**
 * Options for creating a new session
 */
export interface CreateSessionOptions {
  userId: string;
  ipAddress?: string;
  userAgent?: string;
  locationData?: SessionLocation;
  deviceData?: SessionDevice;
  expiresAt?: Date;
  metadata?: Record<string, unknown>;
  host?: string;
}

/**
 * Result of session validation
 */
export interface SessionValidationResult {
  isValid: boolean;
  state: SessionState;
  session?: unknown; // Will use Prisma type
  rotated?: boolean;
  sessionToken?: SessionToken;
  csrfToken?: CsrfToken;
  sessionCookie?: string;
  csrfCookie?: string;
  reason?: string;
}

/**
 * Cookies returned after successful authentication
 */
export interface AuthCookies {
  sessionCookie: string;
  csrfCookie: string;
}
