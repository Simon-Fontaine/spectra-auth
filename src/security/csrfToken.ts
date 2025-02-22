import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "../utils/response";
import { base64Url } from "./base64";
import { createHMAC } from "./hmac";
import { randomBytes } from "./random";

export async function generateCsrfToken({
  config,
}: {
  config: AegisAuthConfig;
}): Promise<AegisResponse<{ csrfToken: string; csrfTokenHash: string }>> {
  try {
    const bytesResponse = randomBytes(config.csrf.tokenLength);
    if (!bytesResponse.success) {
      return fail("CSRF_TOKEN_RANDOM_BYTES_ERROR", bytesResponse.error.message);
    }

    const csrfToken = base64Url.encode(bytesResponse.data);

    const csrfTokenHash = await createHMAC("SHA-256", "base64urlnopad").sign(
      config.csrf.secret,
      csrfToken,
    );

    return success({ csrfToken, csrfTokenHash });
  } catch (error) {
    return fail("CSRF_TOKEN_GENERATION_ERROR", "Failed to generate CSRF token");
  }
}

export async function verifyCsrfToken({
  token,
  hash,
  config,
}: {
  token: string;
  hash: string;
  config: AegisAuthConfig;
}): Promise<AegisResponse<boolean>> {
  try {
    const isValid = await createHMAC("SHA-256", "base64urlnopad").verify(
      config.csrf.secret,
      token,
      hash,
    );
    return success(isValid);
  } catch (error) {
    return fail("CSRF_TOKEN_VERIFICATION_ERROR", "Failed to verify CSRF token");
  }
}
