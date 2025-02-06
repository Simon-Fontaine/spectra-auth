import { serialize } from "cookie";
import { createHMAC } from "../crypto/hmac";

export async function generateCSRFToken(sessionToken: string, secret: string) {
  // HMAC-based approach
  return await createHMAC("SHA-256", "hex").sign(secret, sessionToken);
}

const CSRF_COOKIE_NAME = "spectra.csrfToken";

/**
 * Creates a Set-Cookie string for the CSRF token, which you'll send along with
 * the session cookie.
 */
export async function createCSRFCookie(
  sessionToken: string,
  secret: string,
  maxAgeSeconds: number,
): Promise<string> {
  const csrfToken = await generateCSRFToken(sessionToken, secret);
  return serialize(CSRF_COOKIE_NAME, csrfToken, {
    httpOnly: false, // must be readable by JS so forms can place it in a header or hidden field
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: maxAgeSeconds,
  });
}

/**
 * Validate the CSRF token from the cookie against a token sent in the header
 * (or form field).
 */
export async function validateCSRFToken(
  sessionToken: string,
  secret: string,
  csrfCookieValue: string,
  csrfHeaderOrBodyValue: string,
): Promise<boolean> {
  const expected = await generateCSRFToken(sessionToken, secret);
  return expected === csrfCookieValue && expected === csrfHeaderOrBodyValue;
}

/**
 * Convenient helper to parse the CSRF token from cookie header.
 */
export function getCSRFTokenFromCookies(cookieHeader: string | undefined) {
  if (!cookieHeader) return null;
  const cookies = cookieHeader.split(";").map((c) => c.trim().split("="));
  const cookieObj = Object.fromEntries(cookies);
  return cookieObj[CSRF_COOKIE_NAME] || null;
}
