import type { AegisAuthConfig } from "../types";
import { fail, success } from "../utils/response";
import { base64Url } from "./base64";
import { createHMAC } from "./hmac";
import { randomBytes } from "./random";

export async function generateSessionToken({
  config,
}: { config: AegisAuthConfig }) {
  try {
    const sessionToken = base64Url.encode(
      randomBytes(config.session.tokenLength),
    );

    const sessionTokenHash = await createHMAC("SHA-256", "base64urlnopad").sign(
      config.session.secret,
      sessionToken,
    );

    return success({
      sessionToken,
      sessionTokenHash,
    });
  } catch (error) {
    return fail(
      "SESSION_TOKEN_GENERATION_ERROR",
      "Failed to generate session token",
    );
  }
}

export async function signSessionToken({
  sessionToken,
  config,
}: {
  sessionToken: string;
  config: AegisAuthConfig;
}) {
  try {
    const hash = await createHMAC("SHA-256", "base64urlnopad").sign(
      config.session.secret,
      sessionToken,
    );
    return success(hash);
  } catch (error) {
    return fail("SESSION_TOKEN_SIGNING_ERROR", "Failed to sign session token");
  }
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
  try {
    const isValid = await createHMAC("SHA-256", "base64urlnopad").verify(
      config.session.secret,
      sessionToken,
      sessionTokenHash,
    );
    return success(isValid);
  } catch (error) {
    return fail(
      "SESSION_TOKEN_VERIFICATION_ERROR",
      "Failed to verify session token",
    );
  }
}
