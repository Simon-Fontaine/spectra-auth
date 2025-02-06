import { ArgonType, hash, verify } from "argon2-browser";
import { getRandomValues } from "uncrypto";

/**
 * Interface defining Argon2 options for password hashing.
 */
export interface Argon2Options {
  mem?: number; // Memory cost in kilobytes
  time?: number; // Number of iterations
  parallelism?: number; // Degree of parallelism (threads)
  saltSize?: number; // Salt length in bytes
}

/**
 * Generates a cryptographically secure random salt.
 *
 * @param bytes - The size of the salt in bytes.
 * @returns A Uint8Array containing the random salt.
 */
function generateRandomSalt(bytes: number): Uint8Array {
  const salt = new Uint8Array(bytes);
  getRandomValues(salt);
  return salt;
}

/**
 * Hashes a plaintext password using Argon2id with customizable parameters.
 *
 * @param pass - The plaintext password to hash.
 * @param options - Optional configuration for Argon2 hashing.
 * @returns The Argon2-encoded hash string.
 */
export async function hashArgon2(
  pass: string,
  { mem = 4096, time = 3, parallelism = 1, saltSize = 16 }: Argon2Options = {},
): Promise<string> {
  const result = await hash({
    pass,
    salt: generateRandomSalt(saltSize),
    type: ArgonType.Argon2id,
    mem,
    time,
    parallelism,
  });
  return result.encoded;
}

/**
 * Verifies a plaintext password against an Argon2-encoded hash.
 *
 * @param encoded - The encoded Argon2 hash to verify against.
 * @param pass - The plaintext password to verify.
 * @returns `true` if the password matches the hash, `false` otherwise.
 */
export async function verifyArgon2(
  encoded: string,
  pass: string,
): Promise<boolean> {
  try {
    await verify({
      pass,
      encoded,
      type: ArgonType.Argon2id,
    });
    return true;
  } catch (error) {
    // Log or handle verification errors as needed
    return false;
  }
}
