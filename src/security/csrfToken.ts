import type { AegisAuthConfig } from "../config";
import { base64Url } from "./base64";
import { createHMAC } from "./hmac";
import { randomBytes } from "./random";

export async function generateCsrfToken({
  config,
}: {
  config: AegisAuthConfig;
}) {
  const csrfToken = base64Url.encode(randomBytes(config.csrf.tokenLengthBytes));

  const csrfTokenHash = await createHMAC("SHA-256", "base64urlnopad").sign(
    config.csrf.tokenSecret,
    csrfToken,
  );

  return {
    csrfToken,
    csrfTokenHash,
  };
}

export async function verifyCsrfToken({
  token,
  hash,
  config,
}: {
  token: string;
  hash: string;
  config: AegisAuthConfig;
}) {
  return await createHMAC("SHA-256", "base64urlnopad").verify(
    config.csrf.tokenSecret,
    token,
    hash,
  );
}
