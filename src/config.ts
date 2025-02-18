import type { Redis } from "@upstash/redis";
import { merge } from "lodash";
import type { EndpointName } from "./types";
import { createTime } from "./utils";

// Type Definitions
export interface LoggerConfig {
  info: (message: string, meta?: Record<string, unknown>) => void;
  warn: (message: string, meta?: Record<string, unknown>) => void;
  error: (message: string, meta?: Record<string, unknown>) => void;
}

export interface AuthConfig {
  registration: {
    enabled: boolean;
    requireEmailVerification: boolean;
  };
  login: {
    maxFailedAttempts: number;
    lockoutDurationSeconds: number;
  };
  session: {
    maxSessionsPerUser: number;
  };
  password: {
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
  };
  geo: {
    enabled: boolean;
    maxmindClientId: string;
    maxmindLicenseKey: string;
    maxmindHost: string;
  };
}

export interface SecurityConfig {
  session: {
    secret: string;
    secretLength: number;
    maxLifetimeSeconds: number;
    refreshIntervalSeconds: number;
    cookie: {
      name: string;
      maxAge: number;
      domain?: string;
      path: string;
      httpOnly: boolean;
      secure: boolean;
      sameSite: "strict" | "lax" | "none" | boolean;
    };
  };
  csrf: {
    enabled: boolean;
    secret: string;
    secretLength: number;
    cookie: {
      name: string;
      maxAge: number;
      domain?: string;
      path: string;
      httpOnly: boolean;
      secure: boolean;
      sameSite: "strict" | "lax" | "none" | boolean;
    };
  };
  verification: {
    tokenLength: number;
    tokenExpirySeconds: number;
  };
}

export interface RateLimitEndpointConfig {
  enabled: boolean;
  maxAttempts: number;
  window: number;
}

export interface ProtectionConfig {
  rateLimit: {
    enabled: boolean;
    redis?: Redis;
    prefix: string;
    endpoints: Record<EndpointName, RateLimitEndpointConfig>;
  };
}

export interface EmailTemplate {
  subject: (params: {
    token: string;
    toEmail: string;
    callbackUrl?: string;
  }) => string;
  html: (params: {
    token: string;
    toEmail: string;
    callbackUrl?: string;
  }) => string;
}

export interface CommunicationConfig {
  email: {
    from: string;
    resendApiKey: string;
    templates: Record<string, EmailTemplate>;
  };
}

export interface AegisAuthConfig {
  logger: LoggerConfig;
  core: {
    baseUrl: string;
  };
  auth: AuthConfig;
  security: SecurityConfig;
  protection: ProtectionConfig;
  communication: CommunicationConfig;
}

// Default Configuration
const defaultConfig: AegisAuthConfig = {
  logger: {
    info: console.log,
    warn: console.warn,
    error: console.error,
  },
  core: {
    baseUrl: process.env.BASE_URL || "http://localhost:3000",
  },
  auth: {
    registration: {
      enabled: true,
      requireEmailVerification: true,
    },
    login: {
      maxFailedAttempts: 5,
      lockoutDurationSeconds: createTime(15, "m").toSeconds(),
    },
    session: {
      maxSessionsPerUser: 5,
    },
    password: {
      hash: {
        cost: 16384,
        blockSize: 16,
        parallelization: 1,
        keyLength: 64,
      },
      rules: {
        minLength: 8,
        maxLength: 32,
        requireLowercase: true,
        requireUppercase: true,
        requireNumber: true,
        requireSymbol: true,
      },
    },
    geo: {
      enabled: false,
      maxmindClientId: process.env.MAXMIND_CLIENT_ID || "",
      maxmindLicenseKey: process.env.MAXMIND_LICENSE_KEY || "",
      maxmindHost: "geolite.info",
    },
  },
  security: {
    session: {
      secret: process.env.SESSION_TOKEN_SECRET || "change-me",
      secretLength: 64,
      maxLifetimeSeconds: createTime(30, "d").toSeconds(),
      refreshIntervalSeconds: createTime(1, "h").toSeconds(),
      cookie: {
        name: "aegis.session",
        maxAge: createTime(1, "w").toSeconds(),
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      },
    },
    csrf: {
      enabled: true,
      secret: process.env.CSRF_TOKEN_SECRET || "change-me",
      secretLength: 32,
      cookie: {
        name: "aegis.csrf",
        maxAge: createTime(1, "w").toSeconds(),
        path: "/",
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      },
    },
    verification: {
      tokenLength: 32,
      tokenExpirySeconds: createTime(1, "d").toSeconds(),
    },
  },
  protection: {
    rateLimit: {
      enabled: true,
      prefix: "aegis:rate-limit",
      endpoints: {
        login: {
          enabled: true,
          maxAttempts: 5,
          window: createTime(15, "m").toSeconds(),
        },
        register: {
          enabled: true,
          maxAttempts: 3,
          window: createTime(15, "m").toSeconds(),
        },
        verifyEmail: {
          enabled: true,
          maxAttempts: 3,
          window: createTime(15, "m").toSeconds(),
        },
        initiatePasswordReset: {
          enabled: true,
          maxAttempts: 3,
          window: createTime(15, "m").toSeconds(),
        },
        completePasswordReset: {
          enabled: true,
          maxAttempts: 3,
          window: createTime(15, "m").toSeconds(),
        },
        initiateEmailChange: {
          enabled: true,
          maxAttempts: 3,
          window: createTime(15, "m").toSeconds(),
        },
        completeEmailChange: {
          enabled: true,
          maxAttempts: 3,
          window: createTime(15, "m").toSeconds(),
        },
        initiateAccountDeletion: {
          enabled: true,
          maxAttempts: 3,
          window: createTime(15, "m").toSeconds(),
        },
        completeAccountDeletion: {
          enabled: true,
          maxAttempts: 3,
          window: createTime(15, "m").toSeconds(),
        },
      },
    },
  },
  communication: {
    email: {
      from: "no-reply@example.com",
      resendApiKey: process.env.RESEND_API_KEY || "",
      templates: {},
    },
  },
};

// Configuration Builder
export function buildConfig(
  userConfig?: Partial<AegisAuthConfig>,
): AegisAuthConfig {
  const merged = merge({}, defaultConfig, userConfig);
  const config = merged as AegisAuthConfig;

  // Merge logger configuration
  if (!userConfig?.logger) config.logger = defaultConfig.logger;
  else config.logger = { ...defaultConfig.logger, ...userConfig.logger };

  // Production safety checks
  if (process.env.NODE_ENV === "production") {
    config.security.session.cookie.secure = true;
    config.security.csrf.cookie.secure = true;

    if (config.security.session.secret === "change-me") {
      throw new Error(
        "Please set a secure SESSION_TOKEN_SECRET in production.",
      );
    }
    if (config.security.csrf.secret === "change-me") {
      throw new Error("Please set a secure CSRF_TOKEN_SECRET in production.");
    }
  }

  return config;
}

// Helper Types
export type DeepPartial<T> = {
  [P in keyof T]?: T[P] extends object ? DeepPartial<T[P]> : T[P];
};
