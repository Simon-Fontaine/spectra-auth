import type { PrismaClient } from "@prisma/client";
import { mergeConfig } from "./config/defaults";
import { validateEnv } from "./config/envCheck";
import {
  clearSessionCookie,
  createSessionCookie,
  getSessionTokenFromHeader,
} from "./cookies/simple";
import { csrfFactory } from "./internal/csrfFactory";
import {
  loginUserFactory,
  logoutUserFactory,
} from "./internal/loginLogoutFactories";
import { registerUserFactory } from "./internal/registerFactory";
import {
  completePasswordResetFactory,
  initiatePasswordResetFactory,
} from "./internal/resetFactories";
import {
  createSessionFactory,
  revokeSessionFactory,
  validateSessionFactory,
} from "./internal/sessionFactories";
import {
  createVerificationTokenFactory,
  useVerificationTokenFactory,
  verifyEmailFactory,
} from "./internal/verifyFactories";
import type { SpectraAuthConfig } from "./types";
import { createRateLimiter } from "./utils/rateLimit";

export function initSpectraAuth(
  prisma: PrismaClient,
  userConfig?: SpectraAuthConfig,
) {
  // 1. Validate environment (Upstash keys, etc.)
  validateEnv();

  // 2. Merge user config with defaults
  const config = mergeConfig(userConfig);

  // 3. Create a default rate limiter
  const rateLimiter = createRateLimiter(
    config.rateLimitingStrategy,
    config.attempts,
    config.windowSeconds,
    "login-ip",
  );

  // 4. Build each auth method using factories
  const registerUser = registerUserFactory(prisma, config);
  const loginUser = loginUserFactory(prisma, config, rateLimiter);
  const logoutUser = logoutUserFactory(prisma, config);
  const initiatePasswordReset = initiatePasswordResetFactory(prisma, config);
  const completePasswordReset = completePasswordResetFactory(prisma, config);
  const createSession = createSessionFactory(prisma, config);
  const validateSession = validateSessionFactory(prisma, config);
  const revokeSession = revokeSessionFactory(prisma, config);
  const createVerificationToken = createVerificationTokenFactory(
    prisma,
    config,
  );
  const useVerificationToken = useVerificationTokenFactory(prisma, config);
  const verifyEmail = verifyEmailFactory(prisma, config);

  // 5. Build CSRF methods from the factory
  const { createCSRFCookie, getCSRFTokenFromCookies, validateCSRFToken } =
    csrfFactory(config);

  // 6. Return everything at top-level
  return {
    // Registration
    registerUser,

    // Login / Logout
    loginUser,
    logoutUser,

    // Password reset
    initiatePasswordReset,
    completePasswordReset,

    // Sessions
    createSession,
    validateSession,
    revokeSession,

    // Verification
    createVerificationToken,
    useVerificationToken,
    verifyEmail,

    // Cookies: session
    createSessionCookie,
    clearSessionCookie,
    getSessionTokenFromHeader,

    // Cookies: CSRF
    createCSRFCookie,
    getCSRFTokenFromCookies,
    validateCSRFToken,
  };
}
