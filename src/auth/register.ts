import type { PrismaClient } from "@prisma/client";
import { hashPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthConfig, SpectraAuthResult } from "../types";
import { registerSchema } from "../validation/authSchemas";
import { sendVerificationEmail } from "./email";
import { createVerificationToken } from "./verification";

export interface RegisterOptions {
  /** The desired username. */
  username: string;
  /** The user’s email address. */
  email: string;
  /** The user’s plaintext password. */
  password: string;
}

/**
 * Registers a new user and sends an email verification link.
 */
export async function registerUser(
  prisma: PrismaClient,
  config: Required<SpectraAuthConfig>,
  options: RegisterOptions,
): Promise<SpectraAuthResult> {
  try {
    // 1. Validate input
    const data = registerSchema.parse(options);

    // 2. Hash password
    const hashed = await hashPassword(data.password, config);

    // 3. Create user
    const user = (await prisma.user.create({
      data: {
        username: data.username,
        email: data.email,
        password: hashed,
      },
    })) as AuthUser;

    // 4. Create email verification token
    const token = await createVerificationToken(prisma, config, {
      userId: user.id,
      type: "EMAIL_VERIFICATION",
    });

    // 5. Send email
    await sendVerificationEmail(data.email, token);

    config.logger.info("New user registered", { userId: user.id });

    return {
      error: false,
      status: 201,
      message: "Registration successful. Check your email.",
      data: { userId: user.id },
    };
  } catch (err) {
    config.logger.error("Registration error", { error: err });
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Registration failed",
    };
  }
}
