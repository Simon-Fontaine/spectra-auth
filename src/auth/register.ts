import type { PrismaClient } from "@prisma/client";
import { hashPassword } from "../crypto/password";
import type { AuthUser } from "../interfaces";
import type { SpectraAuthResult } from "../types";
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
 *
 * @param prisma   - The PrismaClient instance.
 * @param options  - { username, email, password }
 * @returns        - A SpectraAuthResult with success or error details.
 */
export async function registerUser(
  prisma: PrismaClient,
  options: RegisterOptions,
): Promise<SpectraAuthResult> {
  try {
    const data = registerSchema.parse(options);

    // Hash password
    const hashed = await hashPassword(data.password);

    // Create user
    const user = (await prisma.user.create({
      data: {
        username: data.username,
        email: data.email,
        password: hashed,
      },
    })) as AuthUser;

    // Create email verification token
    const token = await createVerificationToken(prisma, {
      userId: user.id,
      type: "EMAIL_VERIFICATION",
    });

    // Send email
    await sendVerificationEmail(data.email, token);

    return {
      error: false,
      status: 201,
      message: "Registration successful. Check your email.",
      data: { userId: user.id },
    };
  } catch (err) {
    return {
      error: true,
      status: 500,
      message: (err as Error).message || "Registration failed",
    };
  }
}
