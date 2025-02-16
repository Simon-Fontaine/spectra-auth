import type { AegisAuthConfig } from "../types";
import { base64Url } from "./base64";
import { createHMAC } from "./hmac";
import { randomBytes } from "./random";

export async function generateSessionToken({
  config,
}: { config: AegisAuthConfig }) {
  const sessionToken = base64Url.encode(
    randomBytes(config.security.session.secretLength),
  );

  const sessionTokenHash = await createHMAC("SHA-256", "base64urlnopad").sign(
    config.security.session.secret,
    sessionToken,
  );

  return {
    sessionToken,
    sessionTokenHash,
  };
}

export async function signSessionToken({
  sessionToken,
  config,
}: {
  sessionToken: string;
  config: AegisAuthConfig;
}) {
  return await createHMAC("SHA-256", "base64urlnopad").sign(
    config.security.session.secret,
    sessionToken,
  );
}

export async function verifySessionToken({
  sessionToken,
  sessionTokenHash,
  config,
}: {
  sessionToken: string;
  sessionTokenHash: string;
  config: AegisAuthConfig;
}) {
  return await createHMAC("SHA-256", "base64urlnopad").verify(
    config.security.session.secret,
    sessionToken,
    sessionTokenHash,
  );
}
