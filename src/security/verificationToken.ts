import type { SpectraAuthConfig } from "../config";
import { hex } from "./hex";
import { randomBytes } from "./random";

export async function createVerificationToken({
  config,
}: { config: SpectraAuthConfig }) {
  const verificationToken = hex.encode(
    randomBytes(config.verification.tokenLengthBytes),
  );

  return verificationToken;
}
