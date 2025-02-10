import type { AegisAuthConfig } from "../config";
import { base64Url } from "./base64";
import { createHMAC } from "./hmac";
import { randomBytes } from "./random";

export async function generateSessionToken({
  config,
}: { config: AegisAuthConfig }) {
  const sessionToken = base64Url.encode(
    randomBytes(config.session.tokenLengthBytes),
  );

  const sessionTokenHash = await createHMAC("SHA-256", "base64urlnopad").sign(
    config.session.tokenSecret,
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
    config.session.tokenSecret,
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
    config.session.tokenSecret,
    sessionToken,
    sessionTokenHash,
  );
}
