import { scryptAsync } from "@noble/hashes/scrypt";
import { getRandomValues } from "uncrypto";
import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "../utils/response";
import { timingSafeEqual } from "./compare";
import { decodeHexToBytes, hex } from "./hex";

async function generateKey({
  password,
  salt,
  config,
}: { password: string; salt: string; config: AegisAuthConfig }): Promise<
  AegisResponse<Uint8Array>
> {
  const { cost, blockSize, parallelization, keyLength } = config.password.hash;

  try {
    const key = await scryptAsync(password.normalize("NFKC"), salt, {
      N: cost,
      p: parallelization,
      r: blockSize,
      dkLen: keyLength,
      maxmem: 128 * cost * blockSize * 2,
    });
    return success(key);
  } catch (error) {
    return fail(
      "PASSWORD_KEY_GENERATION_ERROR",
      "Failed to generate password key",
    );
  }
}

export const hashPassword = async ({
  password,
  config,
}: { password: string; config: AegisAuthConfig }): Promise<
  AegisResponse<string>
> => {
  try {
    const salt = hex.encode(getRandomValues(new Uint8Array(16)));
    const keyResponse = await generateKey({ password, salt, config });

    if (!keyResponse.success) {
      return fail("PASSWORD_KEY_GENERATION_ERROR", keyResponse.error.message);
    }

    return success(`${salt}:${hex.encode(keyResponse.data)}`);
  } catch (error) {
    return fail("PASSWORD_HASH_ERROR", "Failed to hash password");
  }
};

export const verifyPassword = async ({
  hash,
  password,
  config,
}: { hash: string; password: string; config: AegisAuthConfig }): Promise<
  AegisResponse<boolean>
> => {
  try {
    const [salt, key] = hash.split(":");
    const targetKeyResponse = await generateKey({ password, salt, config });

    if (!targetKeyResponse.success) {
      return fail(
        "PASSWORD_KEY_GENERATION_ERROR",
        targetKeyResponse.error.message,
      );
    }

    const keyBytes = decodeHexToBytes(key);
    const isValid = timingSafeEqual(targetKeyResponse.data, keyBytes);
    return success(isValid);
  } catch (error) {
    return fail("PASSWORD_VERIFICATION_ERROR", "Failed to verify password");
  }
};
