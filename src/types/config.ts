import type { Redis } from "@upstash/redis";
import type { EndpointName } from "../constants";
import type { AegisContext } from "./context";
import type { FingerprintOptions } from "./session";

/**
 * Enhanced cookie options for modern browsers
 */
export interface EnhancedCookieOptions {
  partitioned?: boolean;
  priority?: "low" | "medium" | "high";
}

/**
 * Basic cookie configuration
 */
export interface CookieOptions {
  name: string;
  maxAgeSeconds: number;
  domain?: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "strict" | "lax" | "none" | boolean;
}

/**
 * Email handler function type
 */
export type EmailHandler = (options: {
  ctx: AegisContext;
  to: string;
  token: string;
}) => Promise<void>;

/**
 * Security alert handler function type
 */
export type SecurityAlertHandler = (options: {
  ctx: AegisContext;
  to: string;
  subject: string;
  activityType: string;
  metadata: Record<string, unknown>;
}) => Promise<void>;

/**
 * Logger configuration
 */
export interface LoggerConfig {
  debug(msg: string, meta?: Record<string, unknown>): void;
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
}

/**
 * IP detection options
 */
export interface IPDetectionOptions {
  trustProxyHeaders: boolean;
  proxyHeaderPrecedence: string[];
  allowPrivateIPs: boolean;
}

/**
 * Core configuration for the authentication system
 */
export interface CoreConfig {
  baseUrl: string;
  environment?: "development" | "test" | "production";
}

/**
 * Account-related settings
 */
export interface AccountConfig {
  requireEmailVerification: boolean;
  reuseOldPasswords: boolean;
  maxPasswordHistory?: number;
  maxSimultaneousSessions: number;
  preventConcurrentSessions?: boolean;
}

/**
 * Registration settings
 */
export interface RegistrationConfig {
  enabled: boolean;
  requireInvitation: boolean;
  allowedDomains?: string[];
  invitationExpiryDays?: number;
}

/**
 * Login and account security settings
 */
export interface LoginConfig {
  maxFailedAttempts: number;
  lockoutDurationSeconds: number;
  progressiveDelays?: boolean;
}

/**
 * Password hashing and validation rules
 */
export interface PasswordConfig {
  hash: {
    cost: number;
    blockSize: number;
    parallelization: number;
    keyLength: number;
  };
  rules: {
    minLength: number;
    maxLength: number;
    requireLowercase: boolean;
    requireUppercase: boolean;
    requireNumber: boolean;
    requireSymbol: boolean;
  };
}

/**
 * Session management configuration
 */
export interface SessionConfig {
  secret: string;
  tokenLength: number;
  refreshIntervalSeconds: number;
  absoluteMaxLifetimeSeconds: number;
  idleTimeoutSeconds?: number;
  rotationFraction: number;
  cookie: CookieOptions;
  enhancedCookieOptions?: EnhancedCookieOptions;
  fingerprintOptions?: FingerprintOptions;
}

/**
 * CSRF protection settings
 */
export interface CsrfConfig {
  enabled: boolean;
  secret: string;
  tokenLength: number;
  cookie: CookieOptions;
  enhancedCookieOptions?: EnhancedCookieOptions;
}

/**
 * Verification token settings
 */
export interface VerificationConfig {
  tokenLength: number;
  tokenExpirySeconds: number;
}

/**
 * Rate limiting configuration
 */
export interface RateLimitConfig {
  enabled: boolean;
  redis?: Redis;
  prefix: string;
  endpoints: Partial<
    Record<
      EndpointName,
      {
        enabled: boolean;
        maxRequests: number;
        windowSeconds: number;
      }
    >
  >;
}

/**
 * Geolocation service configuration
 */
export interface GeoLookupConfig {
  enabled: boolean;
  maxmindClientId: string;
  maxmindLicenseKey: string;
  maxmindHost: string;
}

/**
 * Email notification handlers
 */
export interface EmailConfig {
  sendEmailVerification: EmailHandler;
  sendPasswordReset: EmailHandler;
  sendEmailChange: EmailHandler;
  sendAccountDeletion: EmailHandler;
  sendSecurityAlert?: SecurityAlertHandler;
}

/**
 * Complete authentication configuration
 */
export interface AegisAuthConfig {
  logger?: LoggerConfig;
  core: CoreConfig;
  account: AccountConfig;
  registration: RegistrationConfig;
  login: LoginConfig;
  password: PasswordConfig;
  session: SessionConfig;
  csrf: CsrfConfig;
  verification: VerificationConfig;
  rateLimit: RateLimitConfig;
  geoLookup: GeoLookupConfig;
  email: EmailConfig;
  ipDetection?: IPDetectionOptions;
}
