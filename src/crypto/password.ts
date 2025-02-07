import {
  type Argon2BrowserHashOptions,
  type Argon2VerifyOptions,
  hash,
  verify,
} from "argon2-browser";
import type { SpectraAuthConfig } from "../types";

/**
 * Hash a password using Argon2.
 *
 * @param plainPassword The plaintext password to hash.
 * @param config SpectraAuth configuration.
 * @returns The hashed password string (usually base64 encoded).
 */
export async function hashPassword(
  plainPassword: string,
  config: Required<SpectraAuthConfig>,
): Promise<string> {
  const options: Argon2BrowserHashOptions = {
    pass: plainPassword,
    ...config.passwordHashOptions,
  };

  try {
    const hashResult = await hash(options);
    return hashResult.encoded;
  } catch (error) {
    console.error("Password hashing failed:", error);
    throw new Error("Password hashing failed");
  }
}

/**
 * Verify a plain password against a hashed password using Argon2.
 *
 * @param hashedPassword The hashed password to compare against.
 * @param plainPassword The plaintext password to verify.
 * @param config SpectraAuth configuration.
 * @returns True if the password is valid, false otherwise.
 */
export async function verifyPassword(
  hashedPassword?: string,
  plainPassword?: string,
  config?: Required<SpectraAuthConfig>,
): Promise<boolean> {
  if (!hashedPassword || !plainPassword || !config?.passwordHashOptions.salt) {
    return false;
  }
  const options: Argon2VerifyOptions = {
    pass: plainPassword, // Plain password to verify
    encoded: hashedPassword, // Hashed password to compare against
  };
  try {
    await verify(options);
    return true;
  } catch (error) {
    if (error && typeof error === "object" && "message" in error) {
      console.error("Password verification error:", error.message);
    } else {
      console.error("Password verification error:", error);
    }
    return false;
  }
}
