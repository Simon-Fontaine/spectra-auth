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
  const sessionPrefix = base64Url.encode(
    randomBytes(config.session.tokenPrefixLengthBytes),
  );

  const sessionTokenHash = await createHMAC("SHA-256", "base64urlnopad").sign(
    config.session.tokenSecret,
    sessionToken,
  );

  return {
    sessionToken: `${sessionPrefix}:${sessionToken}`,
    sessionPrefix,
    sessionTokenHash,
  };
}

export async function verifySessionToken({
  token,
  hash,
  config,
}: {
  token: string;
  hash: string;
  config: AegisAuthConfig;
}) {
  return await createHMAC("SHA-256", "base64urlnopad").verify(
    config.session.tokenSecret,
    token,
    hash,
  );
}

export function getSessionTokenPrefix({
  token,
}: {
  token: string;
}) {
  return token.split(":")[0];
}

export async function getSessionTokenHash({
  token,
  config,
}: {
  token: string;
  config: AegisAuthConfig;
}) {
  return await createHMAC("SHA-256", "base64urlnopad").sign(
    config.session.tokenSecret,
    token.split(":")[1],
  );
}

export async function splitSessionToken({
  token,
  config,
}: {
  token: string;
  config: AegisAuthConfig;
}) {
  return {
    tokenPrefix: getSessionTokenPrefix({ token }),
    tokenHash: await getSessionTokenHash({ token, config }),
  };
}
