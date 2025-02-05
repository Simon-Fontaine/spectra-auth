import type { PrismaClient } from "@prisma/client";
import { APP_CONFIG } from "../config";
import { verifyPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthResult } from "../types";
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
}

/**
 * Logs in a user by email/username + password.
 *
 * - Enforces IP-based rate-limiting via Upstash.
 * - Checks if the account is locked (failed attempts).
 * - Creates a new session if successful.
 *
 * @param prisma   - The PrismaClient instance.
 * @param options  - The login options containing user credentials, IP, device info.
 * @returns        - A SpectraAuthResult with either success or error details.
 */
export async function loginUser(
  prisma: PrismaClient,
  options: LoginOptions,
): Promise<SpectraAuthResult> {
  try {
    // Validate input with Zod
    const data = loginSchema.parse(options.input);

    // 1. IP-based rate limit
    if (options.ipAddress) {
      const limit = await limitIPAttempts(options.ipAddress);
      if (!limit.success) {
        return {
          error: true,
          status: 429,
          message: "Too many attempts from your IP. Try again later.",
        };
      }
    }

    // 2. Check if user exists
    const isEmail = data.identifier.includes("@");
    const user = (await prisma.user.findFirst({
      where: isEmail
        ? { email: data.identifier }
        : { username: data.identifier },
    })) as AuthUser | null;

    if (!user || user.isBanned) {
      return { error: true, status: 401, message: "Invalid credentials" };
    }

    // 3. If locked, return error
    if (user.lockedUntil && user.lockedUntil > new Date()) {
      const minsLeft = Math.ceil(
        (user.lockedUntil.getTime() - Date.now()) / 60000,
      );
      return {
        error: true,
        status: 423,
        message: `Account locked. Try again in ~${minsLeft} minutes.`,
      };
    }

    // 4. Verify password
    const isValid = await verifyPassword(user.password, data.password);
    if (!isValid) {
      let newFailedCount = user.failedLoginAttempts + 1;
      let lockedUntil: Date | null = null;

      // If threshold exceeded, lock out
      if (newFailedCount >= APP_CONFIG.accountLockThreshold) {
        lockedUntil = new Date(Date.now() + APP_CONFIG.accountLockDurationMs);
        newFailedCount = 0; // reset or keep counting
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

    // 5. Check if email is verified
    if (!user.isEmailVerified) {
      return { error: true, status: 403, message: "Email not verified." };
    }

    // 6. Reset lock state
    await prisma.user.update({
      where: { id: user.id },
      data: {
        failedLoginAttempts: 0,
        lockedUntil: null,
      },
    });

    // 7. Create session
    const sessionResult = await createSession(prisma, {
      userId: user.id,
      deviceInfo: {
        ipAddress: options.ipAddress,
        ...options.deviceInfo,
      },
    });

    if (sessionResult.error) {
      return sessionResult; // propagate error
    }

    // Return success
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
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Login failed",
    };
  }
}
