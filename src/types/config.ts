import type { Redis } from "@upstash/redis";
import type { AegisContext } from "./context";
import type { EndpointName } from "./rateLimit";

export type CookieOptions = {
  name: string;
  maxAgeSeconds: number;
  domain?: string;
  path: string;
  httpOnly: boolean;
  secure: boolean;
  sameSite: "strict" | "lax" | "none" | boolean;
};

export type EmailHandler = (options: {
  ctx: AegisContext;
  to: string;
  token: string;
}) => Promise<void>;

export interface LoggerConfig {
  info(msg: string, meta?: Record<string, unknown>): void;
  warn(msg: string, meta?: Record<string, unknown>): void;
  error(msg: string, meta?: Record<string, unknown>): void;
  debug(msg: string, meta?: Record<string, unknown>): void;
}

export interface FingerprintOptions {
  enabled: boolean;
  includeIp: boolean;
  strictValidation: boolean;
  maxDevicesPerUser?: number;
}

export interface IPDetectionOptions {
  trustProxyHeaders: boolean;
  proxyHeaderPrecedence: string[];
  allowPrivateIPs: boolean;
}

export interface CoreConfig {
  baseUrl: string;
}

export interface AccountConfig {
  reuseOldPasswords: boolean;
  maxSimultaneousSessions: number;
  requireEmailVerification: boolean;
}

export interface RegistrationConfig {
  enabled: boolean;
  requireInvitation: boolean;
}

export interface LoginConfig {
  maxFailedAttempts: number;
  lockoutDurationSeconds: number;
}

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

export interface SessionConfig {
  secret: string;
  tokenLength: number;
  refreshIntervalSeconds: number;
  absoluteMaxLifetimeSeconds: number;
  rotationFraction: number;
  cookie: CookieOptions;
  fingerprintOptions?: FingerprintOptions;
}

export interface CsrfConfig {
  enabled: boolean;
  secret: string;
  tokenLength: number;
  cookie: CookieOptions;
}

export interface VerificationConfig {
  tokenLength: number;
  tokenExpirySeconds: number;
}

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

export interface GeoLookupConfig {
  enabled: boolean;
  maxmindClientId: string;
  maxmindLicenseKey: string;
  maxmindHost: string;
}

export interface EmailConfig {
  sendEmailVerification: EmailHandler;
  sendPasswordReset: EmailHandler;
  sendEmailChange: EmailHandler;
  sendAccountDeletion: EmailHandler;
}

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
