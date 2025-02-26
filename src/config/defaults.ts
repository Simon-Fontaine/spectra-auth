import type {
  AccountConfig,
  CoreConfig,
  CsrfConfig,
  EmailConfig,
  GeoLookupConfig,
  IPDetectionOptions,
  LoginConfig,
  PasswordConfig,
  RateLimitConfig,
  RegistrationConfig,
  SessionConfig,
  VerificationConfig,
} from "../types";

/**
 * Default core configuration
 */
export const defaultCoreConfig: CoreConfig = {
  baseUrl: process.env.BASE_URL || "http://localhost:3000",
  environment:
    (process.env.NODE_ENV as "development" | "production" | "test") ||
    "development",
};

/**
 * Default account configuration
 */
export const defaultAccountConfig: AccountConfig = {
  requireEmailVerification: true,
  reuseOldPasswords: false,
  maxPasswordHistory: 5,
  maxSimultaneousSessions: 5,
  preventConcurrentSessions: false,
};

/**
 * Default registration configuration
 */
export const defaultRegistrationConfig: RegistrationConfig = {
  enabled: true,
  requireInvitation: false,
  allowedDomains: [],
  invitationExpiryDays: 7,
};

/**
 * Default login configuration
 */
export const defaultLoginConfig: LoginConfig = {
  maxFailedAttempts: 5,
  lockoutDurationSeconds: 30 * 60, // 30 minutes
  progressiveDelays: true,
};

/**
 * Default password configuration
 */
export const defaultPasswordConfig: PasswordConfig = {
  hash: {
    cost: 16384, // scrypt N parameter
    blockSize: 8, // scrypt r parameter
    parallelization: 1, // scrypt p parameter
    keyLength: 64, // scrypt derived key length
  },
  rules: {
    minLength: 8,
    maxLength: 64,
    requireLowercase: true,
    requireUppercase: true,
    requireNumber: true,
    requireSymbol: true,
  },
};

/**
 * Default session configuration
 */
export const defaultSessionConfig: SessionConfig = {
  secret: process.env.SESSION_TOKEN_SECRET || "CHANGE_THIS_DEFAULT_SECRET",
  tokenLength: 64,
  refreshIntervalSeconds: 60 * 60, // 1 hour
  absoluteMaxLifetimeSeconds: 7 * 24 * 60 * 60, // 7 days
  idleTimeoutSeconds: 2 * 60 * 60, // 2 hours
  rotationFraction: 0.5, // Rotate when 50% of refresh interval has passed
  cookie: {
    name: "aegis.session",
    maxAgeSeconds: 7 * 24 * 60 * 60, // 7 days
    path: "/",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
  enhancedCookieOptions: {
    partitioned: false,
    priority: "high",
  },
  fingerprintOptions: {
    enabled: true,
    includeIp: false,
    strictValidation: false,
    maxDevicesPerUser: 5,
  },
};

/**
 * Default CSRF configuration
 */
export const defaultCsrfConfig: CsrfConfig = {
  enabled: true,
  secret: process.env.CSRF_TOKEN_SECRET || "CHANGE_THIS_DEFAULT_SECRET",
  tokenLength: 32,
  cookie: {
    name: "aegis.csrf",
    maxAgeSeconds: 7 * 24 * 60 * 60, // 7 days
    path: "/",
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
  },
  enhancedCookieOptions: {
    partitioned: false,
    priority: "medium",
  },
};

/**
 * Default verification token configuration
 */
export const defaultVerificationConfig: VerificationConfig = {
  tokenLength: 32,
  tokenExpirySeconds: 24 * 60 * 60, // 24 hours
};

/**
 * Default rate limit configuration
 */
export const defaultRateLimitConfig: RateLimitConfig = {
  enabled: true,
  redis: undefined, // Must be provided by user
  prefix: "aegis:rate-limit",
  endpoints: {
    LOGIN: {
      enabled: true,
      maxRequests: 10,
      windowSeconds: 60, // 10 requests per minute
    },
    REGISTER: {
      enabled: true,
      maxRequests: 5,
      windowSeconds: 60, // 5 requests per minute
    },
    VERIFY_EMAIL: {
      enabled: true,
      maxRequests: 5,
      windowSeconds: 60, // 5 requests per minute
    },
    INITIATE_PASSWORD_RESET: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: 60, // 3 requests per minute
    },
    COMPLETE_PASSWORD_RESET: {
      enabled: true,
      maxRequests: 5,
      windowSeconds: 60, // 5 requests per minute
    },
    INITIATE_EMAIL_CHANGE: {
      enabled: true,
      maxRequests: 3,
      windowSeconds: 60, // 3 requests per minute
    },
    COMPLETE_EMAIL_CHANGE: {
      enabled: true,
      maxRequests: 5,
      windowSeconds: 60, // 5 requests per minute
    },
    INITIATE_ACCOUNT_DELETION: {
      enabled: true,
      maxRequests: 2,
      windowSeconds: 60, // 2 requests per minute
    },
    COMPLETE_ACCOUNT_DELETION: {
      enabled: true,
      maxRequests: 2,
      windowSeconds: 60, // 2 requests per minute
    },
  },
};

/**
 * Default geolocation service configuration
 */
export const defaultGeoLookupConfig: GeoLookupConfig = {
  enabled: true,
  maxmindClientId: process.env.MAXMIND_CLIENT_ID || "",
  maxmindLicenseKey: process.env.MAXMIND_LICENSE_KEY || "",
  maxmindHost: "geolite.info",
};

/**
 * Default email notification handlers (these must be overridden by the user)
 */
export const defaultEmailConfig: EmailConfig = {
  sendEmailVerification: async () => {
    throw new Error("Email verification handler not configured");
  },
  sendPasswordReset: async () => {
    throw new Error("Password reset handler not configured");
  },
  sendEmailChange: async () => {
    throw new Error("Email change handler not configured");
  },
  sendAccountDeletion: async () => {
    throw new Error("Account deletion handler not configured");
  },
};

/**
 * Default IP detection options
 */
export const defaultIPDetectionOptions: IPDetectionOptions = {
  trustProxyHeaders: true,
  proxyHeaderPrecedence: [
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "x-client-ip",
    "forwarded",
  ],
  allowPrivateIPs: false,
};
