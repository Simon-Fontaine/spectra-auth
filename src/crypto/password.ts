import { scryptAsync } from "@noble/hashes/scrypt";
import { getRandomValues } from "uncrypto"; // for random salt

// We'll do our own "timingSafeEqual" by comparing arrays
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

// Scrypt config
const SCRYPT_CONFIG = { N: 16384, r: 16, p: 1, dkLen: 64 };

/**
 * Hashes a password using scrypt with a random salt (edge-compatible).
 *
 * @param password - The plaintext password to hash.
 * @returns        The hashed password in format "<salt>:<derivedKey>" (hex).
 */
export async function hashPassword(password: string): Promise<string> {
  const saltArr = new Uint8Array(16);
  getRandomValues(saltArr);

  const derivedKey = await scryptAsync(password.normalize("NFKC"), saltArr, {
    ...SCRYPT_CONFIG,
    maxmem: 128 * SCRYPT_CONFIG.N * SCRYPT_CONFIG.r * 2,
  });

  const saltHex = bufferToHex(saltArr);
  const dkHex = bufferToHex(derivedKey);
  return `${saltHex}:${dkHex}`;
}

/**
 * Verifies a plaintext password against a stored scrypt hash.
 *
 * @param storedHash - The stored hash in format "<salt>:<derivedKey>".
 * @param input      - The plaintext password to check.
 * @returns          True if it matches, false otherwise.
 */
export async function verifyPassword(
  storedHash: string,
  input: string,
): Promise<boolean> {
  const [saltHex, dkHex] = storedHash.split(":");
  if (!saltHex || !dkHex) return false;

  const salt = hexToBuffer(saltHex);
  const targetKey = hexToBuffer(dkHex);

  const derived = await scryptAsync(input.normalize("NFKC"), salt, {
    ...SCRYPT_CONFIG,
    maxmem: 128 * SCRYPT_CONFIG.N * SCRYPT_CONFIG.r * 2,
  });

  return timingSafeEqual(derived, targetKey);
}

/** Helper: converts ArrayBuffer / Uint8Array to hex string. */
function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Helper: converts hex string to Uint8Array. */
function hexToBuffer(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = Number.parseInt(hex.substring(i, i + 2), 16);
  }
  return arr;
}
