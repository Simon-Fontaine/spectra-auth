import { getRandomValues } from "uncrypto";
import type { SpectraAuthConfig } from "../types";
import { base64Url } from "./base64";
import { timingSafeEqual } from "./buffer";
import { createHMAC } from "./hmac";

const CSRF_TOKEN_LENGTH_BYTES = 32; // 32 bytes = 256 bits, good security level
const CSRF_SECRET_LENGTH_BYTES = 32;

function randomBytes(length: number): Uint8Array {
  return getRandomValues(new Uint8Array(length));
}

/**
 * Generates a cryptographically secure CSRF secret.
 * @returns A base64url encoded CSRF secret.
 */
export async function generateCSRFSecret(): Promise<string> {
  return base64Url.encode(randomBytes(CSRF_SECRET_LENGTH_BYTES));
}

/**
 * Generates a CSRF token by combining a random token part and a signature.
 *
 * @param sessionToken The session token associated with the user's session.
 * @param csrfSecret The CSRF secret specific to the session.
 * @param config SpectraAuth configuration.
 * @returns A string representing the CSRF token (tokenPart.signaturePart).
 */
export async function generateCSRFToken(
  sessionToken: string,
  csrfSecret: string,
  config: Required<SpectraAuthConfig>,
): Promise<string> {
  const data = `${sessionToken}.${csrfSecret}`;
  const signature = await createHMAC("SHA-256", "base64urlnopad").sign(
    config.session.csrfSecret,
    data,
  );
  return `${base64Url.encode(randomBytes(CSRF_TOKEN_LENGTH_BYTES))}.${signature}`; // tokenPart.signaturePart
}

/**
 * Validates a submitted CSRF token against the expected values.
 *
 * @param sessionToken The session token from the request cookies.
 * @param csrfCookieToken The CSRF token from the request cookies.
 * @param csrfSubmittedToken The CSRF token submitted in the request header or body.
 * @param csrfSecret The CSRF secret associated with the session.
 * @param config SpectraAuth configuration.
 * @returns True if the CSRF token is valid, false otherwise.
 */
export async function verifyCSRFToken(
  sessionToken: string,
  csrfCookieToken: string | undefined,
  csrfSubmittedToken: string | undefined,
  csrfSecret: string,
  config: Required<SpectraAuthConfig>,
): Promise<boolean> {
  if (!csrfCookieToken || !csrfSubmittedToken) {
    return false;
  }

  const [tokenPart, signaturePart] = csrfSubmittedToken.split(".");
  if (!tokenPart || !signaturePart) {
    return false; // Invalid format
  }

  const expectedSignature = await createHMAC("SHA-256", "base64urlnopad").sign(
    config.session.csrfSecret,
    `${sessionToken}.${csrfSecret}`,
  );

  // Use timingSafeEqual to prevent timing attacks
  const submittedSignatureBuffer = base64Url.decode(signaturePart);
  const expectedSignatureBuffer = base64Url.decode(expectedSignature);

  return timingSafeEqual(submittedSignatureBuffer, expectedSignatureBuffer);
}
