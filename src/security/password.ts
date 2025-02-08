import { scryptAsync } from "@noble/hashes/scrypt";
import { getRandomValues } from "uncrypto";
import type { SpectraAuthConfig } from "../config";
import { timingSafeEqual } from "./compare";
import { hex } from "./hex";

async function generateKey({
  password,
  salt,
  config,
}: { password: string; salt: string; config: SpectraAuthConfig }) {
  const { costFactor, parallelization, blockSize, derivedKeyLength } =
    config.accountSecurity.passwordHashing;

  return await scryptAsync(password.normalize("NFKC"), salt, {
    N: costFactor,
    p: parallelization,
    r: blockSize,
    dkLen: derivedKeyLength,
    maxmem: 128 * costFactor * blockSize * 2,
  });
}

export const hashPassword = async ({
  password,
  config,
}: { password: string; config: SpectraAuthConfig }) => {
  const salt = hex.encode(getRandomValues(new Uint8Array(16)));
  const key = await generateKey({ password, salt, config });
  return `${salt}:${hex.encode(key)}`;
};

export const verifyPassword = async ({
  hash,
  password,
  config,
}: { hash: string; password: string; config: SpectraAuthConfig }) => {
  const [salt, key] = hash.split(":");
  const targetKey = await generateKey({ password, salt, config });
  return timingSafeEqual(targetKey, new Uint8Array(Buffer.from(key, "hex")));
};
