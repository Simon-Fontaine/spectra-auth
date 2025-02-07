import { parse, serialize } from "cookie";
import type { SpectraAuthConfig } from "../types";

/**
 * Creates (or updates) the CSRF cookie with the raw token (unhashed).
 *
 * @param rawToken - The random, raw CSRF token string.
 * @param config   - Required config to know cookie properties (secure, sameSite, etc.).
 * @returns The full "Set-Cookie" header string for this CSRF cookie.
 */
export function createCSRFCookie(
  rawToken: string,
  config: Required<SpectraAuthConfig>,
): string {
  return serialize(config.csrf.cookieName, rawToken, {
    httpOnly: config.csrf.cookieHttpOnly,
    secure: config.csrf.cookieSecure,
    sameSite: config.csrf.cookieSameSite,
    path: "/",
    maxAge: config.csrf.maxAgeSec,
  });
}

/**
 * Clears the CSRF cookie by setting it to an empty value with maxAge=0.
 */
export function clearCSRFCookie(config: Required<SpectraAuthConfig>): string {
  return serialize(config.csrf.cookieName, "", {
    httpOnly: config.csrf.cookieHttpOnly,
    secure: config.csrf.cookieSecure,
    sameSite: config.csrf.cookieSameSite,
    path: "/",
    maxAge: 0,
  });
}

/**
 * Extracts the CSRF token from the Cookie header string.
 *
 * @param cookieHeader - The raw "Cookie" header from the request.
 * @param config       - Needed to read config.csrf.cookieName
 * @returns The raw token string if found, undefined otherwise.
 */
export function getCSRFTokenFromCookies(
  cookieHeader: string | undefined,
  config: Required<SpectraAuthConfig>,
): string | undefined {
  if (!cookieHeader) return undefined;
  const cookies = parse(cookieHeader);
  return cookies[config.csrf.cookieName];
}
