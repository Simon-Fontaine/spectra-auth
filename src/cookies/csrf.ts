import { parse, serialize } from "cookie";
import type { SpectraAuthConfig } from "../types";

/**
 * Creates a CSRF cookie.
 *
 * @param csrfToken The CSRF token value.
 * @param maxAgeSeconds Cookie max-age in seconds. Set to 0 to clear the cookie.
 * @param config SpectraAuth configuration.
 * @returns The serialized CSRF cookie string (for Set-Cookie header).
 */
export function createCSRFCookie(
  csrfToken: string,
  maxAgeSeconds: number,
  config: Required<SpectraAuthConfig>,
): string {
  return serialize("spectra.csrfToken", csrfToken, {
    httpOnly: true,
    secure: config.session.cookieSecure,
    sameSite: config.session.cookieSameSite,
    path: "/",
    maxAge: maxAgeSeconds,
  });
}

/**
 * Clears the CSRF cookie by setting its max-age to 0.
 *
 * @param config SpectraAuth configuration.
 * @returns The serialized CSRF cookie string for clearing (Set-Cookie header).
 */
export function clearCSRFCookie(config: Required<SpectraAuthConfig>): string {
  return createCSRFCookie("", 0, config);
}

/**
 * Extracts the CSRF token from the Cookie header.
 *
 * @param cookieHeader The Cookie header string (or undefined).
 * @returns The CSRF token value or undefined if not found.
 */
export function getCSRFTokenFromCookies(
  cookieHeader: string | undefined,
): string | undefined {
  if (!cookieHeader) {
    return undefined;
  }
  const cookies = parse(cookieHeader);
  return cookies["spectra.csrfToken"];
}
