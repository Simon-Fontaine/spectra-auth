import { scryptAsync } from "@noble/hashes/scrypt";
import { getRandomValues } from "uncrypto";
import type { AegisAuthConfig } from "../types";
import { fail, success } from "../utils/response";
import { timingSafeEqual } from "./compare";
import { decodeHexToBytes, hex } from "./hex";

async function generateKey({
  password,
  salt,
  config,
}: { password: string; salt: string; config: AegisAuthConfig }) {
  const { cost, blockSize, parallelization, keyLength } = config.password.hash;

  return await scryptAsync(password.normalize("NFKC"), salt, {
    N: cost,
    p: parallelization,
    r: blockSize,
    dkLen: keyLength,
    maxmem: 128 * cost * blockSize * 2,
  });
}

export const hashPassword = async ({
  password,
  config,
}: { password: string; config: AegisAuthConfig }) => {
  try {
    const salt = hex.encode(getRandomValues(new Uint8Array(16)));
    const key = await generateKey({ password, salt, config });
    return success(`${salt}:${hex.encode(key)}`);
  } catch (error) {
    return fail("PASSWORD_HASH_ERROR", "Failed to hash password");
  }
};

export const verifyPassword = async ({
  hash,
  password,
  config,
}: { hash: string; password: string; config: AegisAuthConfig }) => {
  try {
    const [salt, key] = hash.split(":");
    const targetKey = await generateKey({ password, salt, config });
    const keyBytes = decodeHexToBytes(key);
    const isValid = timingSafeEqual(targetKey, keyBytes);
    return success(isValid);
  } catch (error) {
    return fail("PASSWORD_VERIFICATION_ERROR", "Failed to verify password");
  }
};
