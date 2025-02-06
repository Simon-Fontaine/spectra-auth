import type { PrismaClient } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import { verifyPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { limitIPAttempts } from "../utils/rateLimit";
import { loginSchema } from "../validation/authSchemas";
import { createSession } from "./session";

export interface LoginInput {
  /** The user’s email or username. */
  identifier: string;
  /** The user’s plaintext password. */
  password: string;
}

export interface LoginOptions {
  /** The credentials input (identifier + password). */
  input: LoginInput;
  /**
   * The IP address of the user for rate-limiting checks.
   * Usually from X-Forwarded-For or request socket IP.
   */
  ipAddress?: string;
  /** Device metadata (location, browser, userAgent, etc.). */
  deviceInfo?: {
    location?: string;
    country?: string;
    device?: string;
    browser?: string;
    userAgent?: string;
  };
  /**
   * If provided, uses this rate limiter instead of the library’s default.
   * For example, the user may want a stricter or separate limiter on login.
   */
  customRateLimiter?: Ratelimit;
}

/**
 * Logs in a user by email/username + password.
 *
 * - Enforces IP-based rate-limiting via Upstash.
 * - Checks if the account is locked (failed attempts).
 * - Creates a new session if successful.
 */
export async function loginUser(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  defaultRateLimiter: Ratelimit | null,
  options: LoginOptions,
): Promise<SpectraAuthResult> {
  try {
    const { logger } = config;

    // 1. Validate input with Zod
    const data = loginSchema.parse(options.input);

    const limiterToUse = options.customRateLimiter ?? defaultRateLimiter;

    // 2. IP-based rate limit
    if (options.ipAddress && !config.disableRateLimit && limiterToUse) {
      const limit = await limitIPAttempts(options.ipAddress, limiterToUse);
      if (!limit.success) {
        logger.warn("IP rate limit exceeded", { ip: options.ipAddress });
        return {
          error: true,
          status: 429,
          message: "Too many attempts from your IP. Try again later.",
          code: "E_RATE_LIMIT",
        };
      }
    }

    // 3. Look up user
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

    // 4. Check lockout
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

    // 5. Verify password
    const isValid = await verifyPassword(user.password, data.password);
    if (!isValid) {
      let newFailedCount = user.failedLoginAttempts + 1;
      let lockedUntil: Date | null = null;

      if (newFailedCount >= config.accountLockThreshold) {
        lockedUntil = new Date(Date.now() + config.accountLockDurationMs);
        newFailedCount = 0; // or keep counting if you prefer
        logger.warn("Lockout triggered", { userId: user.id });
      }

      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: newFailedCount,
          lockedUntil,
        },
      });
      return { error: true, status: 401, message: "Invalid credentials" };
    }

    // 6. Check email verified
    if (!user.isEmailVerified) {
      logger.info("Login attempt on unverified email", { userId: user.id });
      return { error: true, status: 403, message: "Email not verified." };
    }

    // 7. Reset lock state
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });

    // 8. Create session
    const sessionResult = await createSession(prisma, config, {
      userId: user.id,
      deviceInfo: {
        ipAddress: options.ipAddress,
        ...options.deviceInfo,
      },
    });

    if (sessionResult.error) {
      return sessionResult; // propagate error from session creation
    }

    logger.info("Login success", { userId: user.id });

    // 9. Return success
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
