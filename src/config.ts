import type { Redis } from "@upstash/redis";
import { merge } from "lodash";
import { type EndpointName, defaultEndpoints } from "./types";
import type { AegisContext } from "./types/context";
import { createTime } from "./utils";

type CookieOptions = {
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

export interface AegisAuthConfig {
  logger?: {
    info(msg: string, meta?: Record<string, unknown>): void;
    warn(msg: string, meta?: Record<string, unknown>): void;
    error(msg: string, meta?: Record<string, unknown>): void;
  };
  core: {
    baseUrl: string;
  };
  account: {
    reuseOldPasswords: boolean;
    maxSimultaneousSessions: number;
    requireEmailVerification: boolean;
  };
  registration: {
    enabled: boolean;
    requireInvitation: boolean;
  };
  login: {
    maxFailedAttempts: number;
    lockoutDurationSeconds: number;
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
  session: {
    secret: string;
    tokenLength: number;
    refreshIntervalSeconds: number;
    absoluteMaxLifetimeSeconds: number;
    cookie: CookieOptions;
  };
  csrf: {
    enabled: boolean;
    secret: string;
    tokenLength: number;
    cookie: CookieOptions;
  };
  verification: {
    tokenLength: number;
    tokenExpirySeconds: number;
  };
  ratelimit: {
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
  };
  geoLookup: {
    enabled: boolean;
    maxmindClientId: string;
    maxmindLicenseKey: string;
    maxmindHost: string;
  };
  email: {
    sendEmailVerification: EmailHandler;
    sendPasswordReset: EmailHandler;
    sendEmailChange: EmailHandler;
    sendAccountDeletion: EmailHandler;
  };
}

export function buildConfig(
  userConfig: Partial<AegisAuthConfig>,
): AegisAuthConfig {
  const defaultConfig: AegisAuthConfig = {
    core: {
      baseUrl: process.env.BASE_URL || "http://localhost:3000",
    },
    account: {
      reuseOldPasswords: false,
      maxSimultaneousSessions: 5,
      requireEmailVerification: true,
    },
    registration: {
      enabled: true,
      requireInvitation: false,
    },
    login: {
      maxFailedAttempts: 5,
      lockoutDurationSeconds: createTime(30, "m").toSeconds(),
    },
    password: {
      hash: {
        cost: 10,
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
    },
    session: {
      secret: process.env.SESSION_TOKEN_SECRET || "CHANGE_THIS_DEFAULT_SECRET",
      tokenLength: 64,
      refreshIntervalSeconds: createTime(1, "h").toSeconds(),
      absoluteMaxLifetimeSeconds: createTime(30, "d").toSeconds(),
      cookie: {
        name: "aegis.session",
        maxAgeSeconds: createTime(7, "d").toSeconds(),
        path: "/",
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      },
    },
    csrf: {
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
    },
    verification: {
      tokenLength: 32,
      tokenExpirySeconds: createTime(1, "d").toSeconds(),
    },
    ratelimit: {
      enabled: true,
      redis: undefined,
      prefix: "aegis:rate-limit",
      endpoints: {},
    },
    geoLookup: {
      enabled: true,
      maxmindClientId: process.env.MAXMIND_CLIENT_ID || "",
      maxmindLicenseKey: process.env.MAXMIND_LICENSE_KEY || "",
      maxmindHost: "geolite.info",
    },
    email: {
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
    },
  };

  for (const endpoint of defaultEndpoints) {
    defaultConfig.ratelimit.endpoints[endpoint] = {
      enabled: true,
      maxRequests: 5,
      windowSeconds: createTime(15, "m").toSeconds(),
    };
  }

  const mergedConfig = merge({}, defaultConfig, userConfig);

  if (mergedConfig.session.secret === "CHANGE_THIS_DEFAULT_SECRET") {
    throw new Error(
      "AegisAuth: session.secret MUST be set to a strong, random value.",
    );
  }
  if (
    mergedConfig.csrf.enabled &&
    mergedConfig.csrf.secret === "CHANGE_THIS_DEFAULT_SECRET"
  ) {
    throw new Error(
      "AegisAuth: csrf.secret MUST be set to a strong, random value when CSRF protection is enabled.",
    );
  }

  if (!mergedConfig.email.sendEmailVerification) {
    throw new Error(
      "AegisAuth: email.sendEmailVerification function must be provided.",
    );
  }
  if (!mergedConfig.email.sendPasswordReset) {
    throw new Error(
      "AegisAuth: email.sendPasswordReset function must be provided.",
    );
  }
  if (!mergedConfig.email.sendEmailChange) {
    throw new Error(
      "AegisAuth: email.sendEmailChange function must be provided.",
    );
  }
  if (!mergedConfig.email.sendAccountDeletion) {
    throw new Error(
      "AegisAuth: email.sendAccountDeletion function must be provided.",
    );
  }

  return mergedConfig as AegisAuthConfig;
}
