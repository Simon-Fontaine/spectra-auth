import { scryptAsync } from "@noble/hashes/scrypt";
import { getRandomValues } from "uncrypto";
import type { AegisAuthConfig } from "../types";
import { timingSafeEqual } from "./compare";
import { decodeHexToBytes, hex } from "./hex";

async function generateKey({
  password,
  salt,
  config,
}: { password: string; salt: string; config: AegisAuthConfig }) {
  const { cost, blockSize, parallelization, keyLength } =
    config.auth.password.hash;

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
  const salt = hex.encode(getRandomValues(new Uint8Array(16)));
  const key = await generateKey({ password, salt, config });
  return `${salt}:${hex.encode(key)}`;
};

export const verifyPassword = async ({
  hash,
  password,
  config,
}: { hash: string; password: string; config: AegisAuthConfig }) => {
  const [salt, key] = hash.split(":");
  const targetKey = await generateKey({ password, salt, config });
  const keyBytes = decodeHexToBytes(key);
  return timingSafeEqual(targetKey, keyBytes);
};
