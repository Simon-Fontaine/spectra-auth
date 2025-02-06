import { ArgonType, hash, verify } from "argon2-browser";
import { getRandomValues } from "uncrypto";
import type { SpectraAuthConfig } from "../types";

/**
 * Hash a password using Argon2id in a WASM-friendly manner,
 * plus an optional pepper from config.
 */
export async function hashPassword(
  password: string,
  config: Required<SpectraAuthConfig>,
): Promise<string> {
  const peppered = password + config.passwordPepper;

  const result = await hash({
    pass: peppered,
    salt: generateRandomSalt(16),
    type: ArgonType.Argon2id,
    mem: 4096,
    time: 3,
    parallelism: 1,
  });

  return result.encoded;
}

/**
 * Verify a plaintext password against an Argon2 hash.
 */
export async function verifyPassword(
  storedHash: string,
  inputPassword: string,
  config: Required<SpectraAuthConfig>,
): Promise<boolean> {
  const peppered = inputPassword + config.passwordPepper;
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

function generateRandomSalt(bytes: number): Uint8Array {
  const salt = new Uint8Array(bytes);
  getRandomValues(salt);
  return salt;
}
