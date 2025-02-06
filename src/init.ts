import type { PrismaClient } from "@prisma/client";
import { mergeConfig } from "./config/defaults";
import { validateEnv } from "./config/envCheck";
import {
  createCSRFCookie,
  getCSRFTokenFromCookies,
  validateCSRFToken,
} from "./cookies/csrf";
import {
  clearSessionCookie,
  createSessionCookie,
  getSessionTokenFromHeader,
} from "./cookies/simple";
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

/**
 * initSpectraAuth
 *
 * Main function to configure and obtain all auth methods.
 */
export function initSpectraAuth(
  prisma: PrismaClient,
  userConfig?: SpectraAuthConfig,
) {
  // 1. Validate environment (Upstash keys, etc.)
  validateEnv();

  // 2. Merge user config with defaults
  const config = mergeConfig(userConfig);

  // 3. Create a rate limiter instance
  const rateLimiter = createRateLimiter(
    config.rateLimitingStrategy,
    config.attempts,
    config.windowSeconds,
  );

  // 4. Build each method with a closure capturing prisma & config
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

  // 5. Optionally expose CSRF helpers (if enableCSRF is true).
  //    In your application routes, you can decide whether to enforce them.
  //    These are lower-level utilities; you can create higher-level helpers if desired.
  const csrf = {
    createCSRFCookie: async (sessionToken: string) =>
      createCSRFCookie(
        sessionToken,
        config.csrfSecret,
        config.sessionMaxAgeSec,
      ),
    getCSRFTokenFromCookies,
    validateCSRFToken: async (
      sessionToken: string,
      csrfCookieVal: string,
      csrfSubmittedVal: string,
    ) =>
      validateCSRFToken(
        sessionToken,
        config.csrfSecret,
        csrfCookieVal,
        csrfSubmittedVal,
      ),
  };

  // Also export simple session cookie helpers directly
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

    // Cookie helpers
    createSessionCookie,
    clearSessionCookie,
    getSessionTokenFromHeader,

    // CSRF helpers
    csrf,
  };
}
