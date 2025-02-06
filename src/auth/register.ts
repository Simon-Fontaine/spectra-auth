import type { PrismaClient } from "@prisma/client";
import { hashPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { createRouteRateLimiter, limitIPAttempts } from "../utils/rateLimit";
import { registerSchema } from "../validation/authSchemas";
import { sendVerificationEmail } from "./email";
import { createVerificationToken } from "./verification";

/**
 * Registers a new user and sends an email verification link.
 *
 * This method handles input validation, rate limiting, password hashing, and
 * sending verification emails to the user after successful registration.
 *
 * @param prisma - The Prisma client instance for database interactions.
 * @param config - The configuration for authentication, including security policies.
 * @param options - The registration details provided by the user.
 * @returns A result indicating success or failure of the registration process.
 */
export async function registerUser(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: RegisterOptions,
): Promise<SpectraAuthResult> {
  try {
    // Step 1: Enforce IP-based rate limiting if applicable
    const ip = options.ipAddress;
    const routeLimiter = createRouteRateLimiter("register", config);
    if (ip && routeLimiter) {
      const limit = await limitIPAttempts(ip, routeLimiter);
      if (!limit.success) {
        config.logger.warn("IP rate limit exceeded on register", { ip });
        return {
          error: true,
          status: 429,
          message: "Too many attempts. Try again later.",
          code: "E_RATE_LIMIT",
        };
      }
    }

    // Step 2: Validate the registration input
    const data = registerSchema.parse(options);

    // Step 3: Hash the user’s password securely
    const hashedPassword = await hashPassword(data.password, config);

    // Step 4: Create the user in the database
    const user = (await prisma.user.create({
      data: {
        username: data.username,
        email: data.email,
        password: hashedPassword,
      },
    })) as AuthUser;

    // Step 5: Generate an email verification token
    const verificationToken = await createVerificationToken(prisma, config, {
      userId: user.id,
      type: "EMAIL_VERIFICATION",
    });

    // Step 6: Send the verification email to the user
    await sendVerificationEmail(data.email, verificationToken);

    config.logger.info("New user registered", { userId: user.id, ip });

    return {
      error: false,
      status: 201,
      message: "Registration successful. Check your email.",
      data: { userId: user.id },
    };
  } catch (err) {
    if (
      err &&
      typeof err === "object" &&
      "code" in err &&
      err.code === "P2002"
    ) {
      config.logger.warn("Registration attempt with existing username/email", {
        ip: options.ipAddress,
      });
      return {
        error: true,
        status: 400,
        message: "Registration failed. Username or email already exists.",
      };
    }

    config.logger.error("Registration error", { error: err });
    return {
      error: true,
      status: 500,
      message:
        (err as Error).message ||
        "Registration failed. Please try again later.",
    };
  }
}

/** Structure for user registration options */
export interface RegisterOptions {
  /** The desired username. */
  username: string;
  /** The user’s email address. */
  email: string;
  /** The user’s plaintext password. */
  password: string;
  /** The user’s IP address, used for rate limiting purposes. */
  ipAddress?: string;
}
