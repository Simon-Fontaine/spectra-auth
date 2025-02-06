import { ArgonType, hash, verify } from "argon2-browser";
import { getRandomValues } from "uncrypto";

/**
 * Splits a random 32-byte array into prefix (8 bytes) + suffix (24 bytes).
 * The `prefix` is stored in DB for quick lookups; `suffix` is only stored hashed.
 */
export function generateTokenParts(): { prefix: string; suffix: string } {
  const buf = new Uint8Array(32);
  getRandomValues(buf);

  const prefixBytes = buf.slice(0, 8); // 8 bytes => 16 hex chars
  const suffixBytes = buf.slice(8, 32); // 24 bytes => 48 hex chars

  return {
    prefix: bufferToHex(prefixBytes),
    suffix: bufferToHex(suffixBytes),
  };
}

/**
 * Hashes the suffix using Argon2 with a random salt (WASM-compatible).
 * We'll store the entire Argon2-encoded string (which includes the salt).
 */
export async function hashSuffix(suffix: string): Promise<string> {
  const result = await hash({
    pass: suffix,
    salt: generateRandomSalt(16),
    type: ArgonType.Argon2id,
    mem: 1024,
    time: 2, // Lower cost than password hashing (since ephemeral)
    parallelism: 1,
  });
  return result.encoded;
}

/**
 * Verifies the suffix against the stored Argon2 hash.
 */
export async function verifySuffixHash(
  storedHash: string,
  suffix: string,
): Promise<boolean> {
  try {
    await verify({
      pass: suffix,
      encoded: storedHash,
      type: ArgonType.Argon2id,
    });
    return true;
  } catch {
    return false;
  }
}

function generateRandomSalt(bytes: number): Uint8Array {
  const salt = new Uint8Array(bytes);
  getRandomValues(salt);
  return salt;
}

function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}
