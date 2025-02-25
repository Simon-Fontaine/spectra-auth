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
import { createTime } from "../utils";

export const defaultCoreConfig: CoreConfig = {
  baseUrl: process.env.BASE_URL || "http://localhost:3000",
};

export const defaultAccountConfig: AccountConfig = {
  reuseOldPasswords: false,
  maxSimultaneousSessions: 5,
  requireEmailVerification: true,
};

export const defaultRegistrationConfig: RegistrationConfig = {
  enabled: true,
  requireInvitation: false,
};

export const defaultLoginConfig: LoginConfig = {
  maxFailedAttempts: 5,
  lockoutDurationSeconds: createTime(30, "m").toSeconds(),
};

export const defaultPasswordConfig: PasswordConfig = {
  hash: {
    cost: 16384,
    blockSize: 8,
    parallelization: 1,
    keyLength: 64,
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

export const defaultSessionConfig: SessionConfig = {
  secret: process.env.SESSION_TOKEN_SECRET || "CHANGE_THIS_DEFAULT_SECRET",
  tokenLength: 64,
  refreshIntervalSeconds: createTime(1, "h").toSeconds(),
  absoluteMaxLifetimeSeconds: createTime(30, "d").toSeconds(),
  idleTimeoutSeconds: createTime(2, "h").toSeconds(),
  rotationFraction: 0.5,
  cookie: {
    name: "aegis.session",
    maxAgeSeconds: createTime(7, "d").toSeconds(),
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

export const defaultCsrfConfig: CsrfConfig = {
  enabled: true,
  secret: process.env.CSRF_TOKEN_SECRET || "CHANGE_THIS_DEFAULT_SECRET",
  tokenLength: 32,
  cookie: {
    name: "aegis.csrf",
    maxAgeSeconds: createTime(7, "d").toSeconds(),
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

export const defaultVerificationConfig: VerificationConfig = {
  tokenLength: 32,
  tokenExpirySeconds: createTime(1, "d").toSeconds(),
};

export const defaultRateLimitConfig: RateLimitConfig = {
  enabled: true,
  redis: undefined,
  prefix: "aegis:rate-limit",
  endpoints: {},
};

export const defaultGeoLookupConfig: GeoLookupConfig = {
  enabled: true,
  maxmindClientId: process.env.MAXMIND_CLIENT_ID || "",
  maxmindLicenseKey: process.env.MAXMIND_LICENSE_KEY || "",
  maxmindHost: "geolite.info",
};

export const defaultEmailConfig: EmailConfig = {
  sendEmailVerification: async () => {
    throw new Error("Email handler not configured");
  },
  sendPasswordReset: async () => {
    throw new Error("Email handler not configured");
  },
  sendEmailChange: async () => {
    throw new Error("Email handler not configured");
  },
  sendAccountDeletion: async () => {
    throw new Error("Email handler not configured");
  },
};

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
