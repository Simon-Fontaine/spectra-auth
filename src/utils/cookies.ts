import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import type {
  AegisAuthConfig,
  CookieOptions,
  EnhancedCookieOptions,
} from "../types";

/**
 * Creates a cookie string with enhanced options support
 *
 * @param name - Cookie name
 * @param value - Cookie value
 * @param options - Standard cookie options
 * @param enhanced - Enhanced cookie options for modern browsers
 * @returns A cookie string for Set-Cookie header
 */
export function createCookie(
  name: string,
  value: string,
  options: Omit<CookieOptions, "name">,
  enhanced?: EnhancedCookieOptions,
): string {
  let cookie = serializeCookie(name, value, {
    ...options,
    maxAge: options.maxAgeSeconds,
  });

  // Add enhanced options if provided
  if (enhanced) {
    if (enhanced.partitioned) {
      cookie += "; Partitioned";
    }

    if (enhanced.priority) {
      cookie += `; Priority=${enhanced.priority}`;
    }
  }

  return cookie;
}

/**
 * Creates a session cookie with configuration
 *
 * @param sessionToken - Session token to store
 * @param config - Auth configuration
 * @returns A formatted session cookie string
 */
export function createSessionCookie(
  sessionToken: string,
  config: AegisAuthConfig,
): string {
  const { name, ...cookieOptions } = config.session.cookie;

  return createCookie(
    name,
    sessionToken,
    cookieOptions,
    config.session.enhancedCookieOptions,
  );
}

/**
 * Creates a CSRF cookie with configuration
 *
 * @param csrfToken - CSRF token to store
 * @param config - Auth configuration
 * @returns A formatted CSRF cookie string
 */
export function createCsrfCookie(
  csrfToken: string,
  config: AegisAuthConfig,
): string {
  const { name, ...cookieOptions } = config.csrf.cookie;

  return createCookie(
    name,
    csrfToken,
    cookieOptions,
    config.csrf.enhancedCookieOptions,
  );
}

/**
 * Creates a cookie clearing string
 *
 * @param name - Cookie name to clear
 * @param options - Cookie options
 * @param enhanced - Enhanced cookie options
 * @returns A cookie string that will clear the named cookie
 */
export function clearCookie(
  name: string,
  options: Omit<CookieOptions, "name" | "maxAgeSeconds">,
  enhanced?: EnhancedCookieOptions,
): string {
  return createCookie(
    name,
    "",
    {
      ...options,
      maxAgeSeconds: 0,
    },
    enhanced,
  );
}

/**
 * Clears the session cookie
 *
 * @param config - Auth configuration
 * @returns A cookie string that will clear the session cookie
 */
export function clearSessionCookie(config: AegisAuthConfig): string {
  const { name, maxAgeSeconds, ...cookieOptions } = config.session.cookie;

  return clearCookie(name, cookieOptions, config.session.enhancedCookieOptions);
}

/**
 * Clears the CSRF cookie
 *
 * @param config - Auth configuration
 * @returns A cookie string that will clear the CSRF cookie
 */
export function clearCsrfCookie(config: AegisAuthConfig): string {
  const { name, maxAgeSeconds, ...cookieOptions } = config.csrf.cookie;

  return clearCookie(name, cookieOptions, config.csrf.enhancedCookieOptions);
}

/**
 * Gets both session and CSRF cookies cleared
 *
 * @param config - Auth configuration
 * @returns Object with both cookies cleared
 */
export function getClearCookies(config: AegisAuthConfig): {
  sessionCookie: string;
  csrfCookie: string;
} {
  return {
    sessionCookie: clearSessionCookie(config),
    csrfCookie: clearCsrfCookie(config),
  };
}

/**
 * Extracts a named cookie from request headers
 *
 * @param headers - Request headers
 * @param name - Cookie name to extract
 * @returns The cookie value or undefined if not found
 */
export function getCookieFromHeaders(
  headers: Headers,
  name: string,
): string | undefined {
  const cookieHeader = headers.get("cookie");
  if (!cookieHeader) return undefined;

  const cookies = parseCookie(cookieHeader);
  return cookies[name];
}

/**
 * Gets the session token from request headers
 *
 * @param headers - Request headers
 * @param config - Auth configuration
 * @returns Session token or undefined if not found
 */
export function getSessionToken(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  return getCookieFromHeaders(headers, config.session.cookie.name);
}

/**
 * Gets the CSRF token from request headers
 *
 * @param headers - Request headers
 * @param config - Auth configuration
 * @returns CSRF token or undefined if not found
 */
export function getCsrfToken(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  return getCookieFromHeaders(headers, config.csrf.cookie.name);
}
