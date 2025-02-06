import { getRandomValues } from "uncrypto";
import { hashArgon2, verifyArgon2 } from "./argon2Utils";

/**
 * Splits a randomly generated 32-byte array into a prefix and suffix.
 *
 * - The `prefix` (8 bytes) is stored in the database for quick token lookups.
 * - The `suffix` (24 bytes) is only stored as a securely hashed value.
 *
 * @returns An object containing the token `prefix` and `suffix`.
 */
export function generateTokenParts(): { prefix: string; suffix: string } {
  const buf = new Uint8Array(32);
  getRandomValues(buf);

  const prefixBytes = buf.slice(0, 8); // 8 bytes => 16 hex characters
  const suffixBytes = buf.slice(8, 32); // 24 bytes => 48 hex characters

  return {
    prefix: bufferToHex(prefixBytes),
    suffix: bufferToHex(suffixBytes),
  };
}

/**
 * Hashes the token suffix using Argon2id.
 *
 * - Argon2 hashing adds computational cost to deter brute-force attacks.
 * - Uses a random salt and parameters optimized for WASM environments.
 *
 * @param suffix - The token suffix to be securely hashed.
 * @returns A promise resolving to the Argon2-encoded string.
 */
export async function hashSuffix(suffix: string): Promise<string> {
  return hashArgon2(suffix, {
    mem: 2048, // Increased memory usage for better security
    time: 3, // Increased iterations for higher resistance to cracking
    parallelism: 1, // Single thread (WASM-friendly)
    saltSize: 16, // 128-bit salt for randomness
  });
}

/**
 * Verifies the token suffix against the stored Argon2 hash.
 *
 * @param storedHash - The Argon2-encoded hash stored in the database.
 * @param suffix - The plain suffix to be verified.
 * @returns A promise resolving to `true` if the suffix is valid, otherwise `false`.
 */
export async function verifySuffixHash(
  storedHash: string,
  suffix: string,
): Promise<boolean> {
  return verifyArgon2(storedHash, suffix);
}

/**
 * Converts a Uint8Array buffer into a hexadecimal string.
 *
 * @param buf - The buffer to convert.
 * @returns The hexadecimal representation of the buffer.
 */
function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}
