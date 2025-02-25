import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "../utils/response";
import { base64Url } from "./base64";
import { createHMAC } from "./hmac";
import { randomBytes } from "./random";

/**
 * Generates a new session token and its corresponding hash
 *
 * @param config - Authentication configuration
 * @returns A response with the session token and its hash, or an error
 */
export async function generateSessionToken({
  config,
}: {
  config: AegisAuthConfig;
}): Promise<
  AegisResponse<{
    sessionToken: string;
    sessionTokenHash: string;
  }>
> {
  try {
    // Generate cryptographically secure random bytes
    const bytesResponse = randomBytes(config.session.tokenLength);
    if (!bytesResponse.success) {
      return fail("SESSION_TOKEN_BYTES_ERROR", bytesResponse.error.message);
    }

    // Convert bytes to URL-safe base64 string
    const sessionToken = base64Url.encode(bytesResponse.data);

    // Create HMAC hash of the token using the session secret
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
      `Failed to generate session token: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Creates a hash of a session token for verification
 *
 * @param sessionToken - The session token to sign
 * @param config - Authentication configuration
 * @returns A response with the token hash or an error
 */
export async function signSessionToken({
  sessionToken,
  config,
}: {
  sessionToken: string;
  config: AegisAuthConfig;
}): Promise<AegisResponse<string>> {
  try {
    // Validate input
    if (!sessionToken) {
      return fail(
        "SESSION_TOKEN_SIGNING_ERROR",
        "Session token cannot be empty",
      );
    }

    // Sign using HMAC with SHA-256
    const hash = await createHMAC("SHA-256", "base64urlnopad").sign(
      config.session.secret,
      sessionToken,
    );
    return success(hash);
  } catch (error) {
    return fail(
      "SESSION_TOKEN_SIGNING_ERROR",
      `Failed to sign session token: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Verifies a session token against its stored hash
 *
 * @param sessionToken - The session token from the client
 * @param sessionTokenHash - The stored hash to verify against
 * @param config - Authentication configuration
 * @returns A response with a boolean indicating validity
 */
export async function verifySessionToken({
  sessionToken,
  sessionTokenHash,
  config,
}: {
  sessionToken: string;
  sessionTokenHash: string;
  config: AegisAuthConfig;
}): Promise<AegisResponse<boolean>> {
  try {
    // Validate inputs
    if (!sessionToken || !sessionTokenHash) {
      return fail(
        "SESSION_TOKEN_VERIFICATION_ERROR",
        "Token or hash cannot be empty",
      );
    }

    // Verify token using HMAC
    const isValid = await createHMAC("SHA-256", "base64urlnopad").verify(
      config.session.secret,
      sessionToken,
      sessionTokenHash,
    );

    return success(isValid);
  } catch (error) {
    return fail(
      "SESSION_TOKEN_VERIFICATION_ERROR",
      `Failed to verify session token: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
