import { scryptAsync } from "@noble/hashes/scrypt";
import { getRandomValues } from "uncrypto";

// We'll define a local timing safe compare
function timingSafeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}

const SCRYPT_CONFIG = { N: 16384, r: 16, p: 1, dkLen: 64 };

/**
 * Splits a random 32-byte array into prefix (8 bytes) + suffix (24 bytes).
 */
export function generateTokenParts(): { prefix: string; suffix: string } {
  const buf = new Uint8Array(32);
  getRandomValues(buf);

  const prefix = bufferToHex(buf.slice(0, 8)); // 16 hex chars
  const suffix = bufferToHex(buf.slice(8, 32)); // 48 hex chars
  return { prefix, suffix };
}

/**
 * Hashes the suffix using scrypt with a random salt (edge-compatible).
 *
 * @param suffix - The raw suffix to be hashed.
 * @returns      The salt + scrypt derived key in hex format "salt:dk".
 */
export async function hashSuffix(suffix: string): Promise<string> {
  const saltArr = new Uint8Array(16);
  getRandomValues(saltArr);

  const derived = await scryptAsync(suffix, saltArr, {
    ...SCRYPT_CONFIG,
    maxmem: 128 * SCRYPT_CONFIG.N * SCRYPT_CONFIG.r * 2,
  });

  return `${bufferToHex(saltArr)}:${bufferToHex(derived)}`;
}

/**
 * Verifies the suffix against the stored scrypt hash.
 *
 * @param stored - The stored hash in format "salt:dk".
 * @param input  - The raw suffix to verify.
 * @returns      True if it matches, false otherwise.
 */
export async function verifySuffixHash(
  stored: string,
  input: string,
): Promise<boolean> {
  const [saltHex, dkHex] = stored.split(":");
  if (!saltHex || !dkHex) return false;

  const salt = hexToBuffer(saltHex);
  const targetKey = hexToBuffer(dkHex);

  const derived = await scryptAsync(input, salt, {
    ...SCRYPT_CONFIG,
    maxmem: 128 * SCRYPT_CONFIG.N * SCRYPT_CONFIG.r * 2,
  });

  return timingSafeEqual(derived, targetKey);
}

/** Helper to convert buffer to hex. */
function bufferToHex(buf: Uint8Array): string {
  return [...buf].map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Helper to convert hex string to Uint8Array. */
function hexToBuffer(hex: string): Uint8Array {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    arr[i / 2] = Number.parseInt(hex.substring(i, i + 2), 16);
  }
  return arr;
}
