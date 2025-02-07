import type { SpectraAuthConfig } from "../types";
import { hashArgon2, verifyArgon2 } from "./argon2Utils";

/**
 * Hashes a password using Argon2id with additional security provided by a pepper.
 *
 * - Appends a server-side secret pepper to the password before hashing.
 * - Uses Argon2id for enhanced protection against GPU-based attacks.
 * - Configurable memory, iterations, and parallelism for fine-tuned security.
 *
 * @param password - The plaintext password to be hashed.
 * @param config - The authentication configuration containing the pepper.
 * @returns The Argon2-encoded hash string.
 */
export async function hashPassword(
  password: string,
  config: Required<SpectraAuthConfig>,
): Promise<string> {
  try {
    // Step 1: Append the server-side pepper to the password
    const peppered = password + config.passwordPepper;

    // Step 2: Hash the password using Argon2id with secure parameters
    return await hashArgon2(peppered, {
      mem: 1024 * 64, // 64 MB memory cost
      time: 3, // 3 iterations
      parallelism: 1, // Single thread (suitable for WASM environments)
      saltSize: 16, // 128-bit salt for randomness
    });
  } catch (err) {
    config.logger.error("Failed to hash password", { error: err });
    throw new Error("Password hashing failed");
  }
}

/**
 * Verifies a plaintext password against a stored Argon2-encoded hash.
 *
 * - Appends the server-side pepper to the input password before verification.
 * - Compares the generated hash with the stored hash securely.
 *
 * @param storedHash - The Argon2-encoded hash stored in the database.
 * @param inputPassword - The plaintext password provided by the user.
 * @param config - The authentication configuration containing the pepper.
 * @returns `true` if the password matches the stored hash, otherwise `false`.
 */
export async function verifyPassword(
  storedHash: string,
  inputPassword: string,
  config: Required<SpectraAuthConfig>,
): Promise<boolean> {
  try {
    // Step 1: Append the server-side pepper to the input password
    const peppered = inputPassword + config.passwordPepper;

    // Step 2: Verify the password against the stored Argon2 hash
    return await verifyArgon2(storedHash, peppered);
  } catch (err) {
    config.logger.warn("Password verification failed", { error: err });
    return false;
  }
}
