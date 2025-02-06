import type { PrismaClient } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import { verifyPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { createRouteRateLimiter, limitIPAttempts } from "../utils/rateLimit";
import { loginSchema } from "../validation/authSchemas";
import { createSession } from "./session";

/**
 * Logs in a user by validating their credentials and creating a session.
 *
 * - Protects against brute-force attacks using rate-limiting.
 * - Handles account lockout after repeated failed attempts.
 * - Verifies credentials and resets failed attempts upon success.
 *
 * @param prisma - The Prisma client instance.
 * @param config - Authentication configuration with logger and security policies.
 * @param defaultRateLimiter - Global rate limiter fallback.
 * @param options - Login options including credentials and device metadata.
 * @returns A result indicating success or failure of the login operation.
 */
export async function loginUser(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  defaultRateLimiter: Ratelimit | null,
  options: LoginOptions,
): Promise<SpectraAuthResult> {
  try {
    const { logger } = config;

    // Step 1: Determine rate limiter to use (route-specific, custom, or default)
    const routeLimiter = createRouteRateLimiter("login", config);
    const limiterToUse =
      routeLimiter ?? options.customRateLimiter ?? defaultRateLimiter;

    // Step 2: Enforce IP-based rate-limiting if IP address is available
    if (options.ipAddress && !config.rateLimit.disable && limiterToUse) {
      const limit = await limitIPAttempts(options.ipAddress, limiterToUse);
      if (!limit.success) {
        logger.warn("IP rate limit exceeded on login", {
          ip: options.ipAddress,
        });
        return {
          error: true,
          status: 429,
          message: "Too many attempts. Try again later.",
          code: "E_RATE_LIMIT",
        };
      }
    }

    // Step 3: Validate input and parse the login data
    const data = loginSchema.parse(options.input);

    // Step 4: Lookup user by email or username
    const isEmail = data.identifier.includes("@");
    const user = (await prisma.user.findFirst({
      where: isEmail
        ? { email: data.identifier }
        : { username: data.identifier },
    })) as AuthUser | null;

    if (!user || user.isBanned) {
      logger.warn("Invalid credentials or banned user", {
        identifier: data.identifier,
      });
      return { error: true, status: 401, message: "Invalid credentials" };
    }

    // Step 5: Check for account lockout
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const minsLeft = Math.ceil(
        (user.lockedUntil.getTime() - Date.now()) / 60000,
      );
      logger.warn("Login attempt but user locked", { userId: user.id });
      return {
        error: true,
        status: 423,
        message: `Account locked. Try again in ~${minsLeft} minutes.`,
        code: "E_LOCKED",
      };
    }

    // Step 6: Verify the user's password
    const isValid = await verifyPassword(user.password, data.password, config);
    if (!isValid) {
      logger.info("Failed password attempt", {
        userId: user.id,
        ip: options.ipAddress,
      });
      let newFailedCount = user.failedLoginAttempts + 1;
      let lockedUntil: Date | null = null;

      if (newFailedCount >= config.accountLock.threshold) {
        lockedUntil = new Date(Date.now() + config.accountLock.durationMs);
        newFailedCount = 0; // Reset on lockout
        logger.warn("Lockout triggered", { userId: user.id });
      }

      await prisma.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts: newFailedCount, lockedUntil },
      });
      return { error: true, status: 401, message: "Invalid credentials" };
    }

    // Step 7: Ensure the user's email is verified
    if (!user.isEmailVerified) {
      logger.info("Login attempt on unverified email", { userId: user.id });
      return { error: true, status: 403, message: "Email not verified." };
    }

    // Step 8: Reset failed login attempts and lockout state upon successful authentication
    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });

    // Step 9: Create a new session
    const sessionResult = await createSession(prisma, config, {
      userId: user.id,
      deviceInfo: {
        ipAddress: options.ipAddress,
        ...options.deviceInfo,
      },
    });

    if (sessionResult.error) {
      return sessionResult; // Propagate session creation error
    }

    logger.info("Login success", {
      userId: user.id,
      tokenPrefix: `${(sessionResult.data?.rawToken as string)?.slice(0, 8)}...`,
    });

    // Step 10: Return success response with session token
    return {
      error: false,
      status: 200,
      message: "Login success",
      data: {
        userId: user.id,
        rawToken: sessionResult.data?.rawToken,
      },
    };
  } catch (err) {
    config.logger.error("Unhandled error in loginUser", { error: err });
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Login failed",
    };
  }
}

/** Input structure for user login */
export interface LoginInput {
  /** The user’s email or username. */
  identifier: string;
  /** The user’s plaintext password. */
  password: string;
}

/** Options for handling user login */
export interface LoginOptions {
  /** The credentials input (identifier + password). */
  input: LoginInput;
  /** The IP address of the user for rate-limiting checks. */
  ipAddress?: string;
  /** Device metadata (location, browser, etc.) */
  deviceInfo?: {
    location?: string;
    country?: string;
    device?: string;
    browser?: string;
    userAgent?: string;
  };
  /** Optional custom rate limiter. */
  customRateLimiter?: Ratelimit;
}
