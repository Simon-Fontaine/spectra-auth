import type { AegisAuthConfig } from "../config";
import { hex } from "./hex";
import { randomBytes } from "./random";

export async function createVerificationToken({
  config,
}: { config: AegisAuthConfig }) {
  const verificationToken = hex.encode(
    randomBytes(config.verification.tokenLength),
  );

  return verificationToken;
}
