import type { AegisAuthConfig } from "../types";
import { hex } from "./hex";
import { randomBytes } from "./random";

export async function createVerificationToken({
  config,
}: { config: AegisAuthConfig }) {
  const verificationToken = hex.encode(
    randomBytes(config.security.verification.tokenLength),
  );

  return verificationToken;
}
