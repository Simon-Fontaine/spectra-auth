import type { PrismaClient } from "@prisma/client";
import { mergeConfig } from "./config/defaults";
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
import { validateConfig } from "./validation/configSchema";

/**
 * Initializes the SpectraAuth library.
 *
 * - Merges the default configuration with user-provided values.
 * - Initializes authentication methods, session handling, and rate-limiting.
 * - Returns a collection of ready-to-use authentication functions.
 *
 * @param prisma - The Prisma client instance.
 * @param userConfig - Optional user configuration for authentication settings.
 * @returns An object containing all the authentication methods and utilities.
 */
export function initSpectraAuth<T extends PrismaClient>(
  prisma: T,
  userConfig?: SpectraAuthConfig,
) {
  // Step 1: Merge the user-provided config with defaults
  const config = mergeConfig(userConfig);
  try {
    validateConfig(config);
  } catch (err) {
    throw new Error(`Invalid configuration: ${(err as Error).message}`);
  }

  // Step 2: Validate rate limiting configuration if enabled
  if (!config.rateLimit.disable) {
    if (!config.rateLimit.kvRestApiUrl || !config.rateLimit.kvRestApiToken) {
      throw new Error(
        "Rate limiting is enabled, but Upstash credentials are missing.",
      );
    }
  }

  // Step 3: Initialize authentication methods using factories
  const registerUser = registerUserFactory(prisma, config);
  const loginUser = loginUserFactory(prisma, config);
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

  // Step 4: Initialize CSRF protection methods
  const { createCSRFCookie, getCSRFTokenFromCookies, validateCSRFToken } =
    csrfFactory(prisma, config);

  // Step 5: Return all methods in a single object
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

    // Cookies: session management
    createSessionCookie,
    clearSessionCookie,
    getSessionTokenFromHeader,

    // Cookies: CSRF protection
    createCSRFCookie,
    getCSRFTokenFromCookies,
    validateCSRFToken,
  };
}
