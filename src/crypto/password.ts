import { ArgonType, hash, verify } from "argon2-browser";
import { getRandomValues } from "uncrypto";
import type { SpectraAuthConfig } from "../types";

/**
 * Hash a password using argon2id in a WASM-friendly manner,
 * plus an optional pepper from config.
 */
export async function hashPassword(
  password: string,
  config: Required<SpectraAuthConfig>,
): Promise<string> {
  const peppered = password + (config.passwordPepper ?? "");

  // Argon2-browser options
  const result = await hash({
    pass: peppered,
    salt: generateRandomSalt(16),
    type: ArgonType.Argon2id,
    mem: 4096, // tune memory (in KB) for your environment
    time: 3, // number of iterations
    parallelism: 1, // concurrency
  });

  return result.encoded;
}

/**
 * Verify password against an argon2 encoded hash.
 */
export async function verifyPassword(
  storedHash: string,
  inputPassword: string,
  config: Required<SpectraAuthConfig>,
): Promise<boolean> {
  const peppered = inputPassword + (config.passwordPepper ?? "");
  try {
    await verify({
      pass: peppered,
      encoded: storedHash,
      type: ArgonType.Argon2id,
    });
    return true;
  } catch (e) {
    return false;
  }
}

/**
 * Because edge runtime might not have Node `crypto`, use something like
 * `crypto.getRandomValues()` from Web Crypto or `uncrypto`.
 */
function generateRandomSalt(bytes: number): Uint8Array {
  const salt = new Uint8Array(bytes);
  getRandomValues(salt);
  return salt;
}
