import { parse, serialize } from "cookie";
import type { SpectraAuthConfig } from "../types";
/**
 * Creates a session cookie.
 *
 * @param sessionToken The session token value.
 * @param maxAgeSeconds Cookie max-age in seconds.
 * @param config SpectraAuth configuration.
 * @returns The serialized session cookie string (for Set-Cookie header).
 */
export function createSessionCookie(
  sessionToken: string,
  maxAgeSeconds: number,
  config: Required<SpectraAuthConfig>,
): string {
  return serialize("spectra.sessionToken", sessionToken, {
    httpOnly: true,
    secure: config.session.cookieSecure,
    sameSite: config.session.cookieSameSite,
    path: "/",
    maxAge: maxAgeSeconds,
  });
}

/**
 * Clears the session cookie by setting its max-age to 0.
 *
 * @param config SpectraAuth configuration.
 * @returns The serialized session cookie string for clearing (Set-Cookie header).
 */
export function clearSessionCookie(
  config: Required<SpectraAuthConfig>,
): string {
  return createSessionCookie("", 0, config);
}

/**
 * Extracts the session token from the Cookie header.
 *
 * @param cookieHeader The Cookie header string (or undefined).
 * @returns The session token value or undefined if not found.
 */
export function getSessionTokenFromHeader(
  cookieHeader: string | undefined,
): string | undefined {
  if (!cookieHeader) {
    return undefined;
  }
  const cookies = parse(cookieHeader);
  return cookies["spectra.sessionToken"];
}
