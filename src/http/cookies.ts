import { parse as parseCookie, serialize } from "cookie";
import type { AegisAuthConfig, CookieOptions } from "../types";

/**
 * Enhanced cookie options with modern browser features
 */
export interface SerializeCookieOptions extends Omit<CookieOptions, "name"> {
  partitioned?: boolean;
  priority?: "low" | "medium" | "high";
}

/**
 * Serializes a cookie with standard and enhanced options
 *
 * @param name - Cookie name
 * @param value - Cookie value
 * @param options - Cookie options
 * @returns Cookie string for Set-Cookie header
 */
export function serializeCookie(
  name: string,
  value: string,
  options: SerializeCookieOptions,
): string {
  const {
    maxAgeSeconds,
    httpOnly,
    secure,
    path,
    domain,
    sameSite,
    partitioned,
    priority,
  } = options;

  // Convert to cookie library format
  let cookie = serialize(name, value, {
    maxAge: maxAgeSeconds,
    httpOnly,
    secure,
    path,
    domain,
    sameSite:
      sameSite === true ? "strict" : sameSite === false ? "none" : sameSite,
  });

  // Add enhanced options if supported
  if (partitioned) {
    cookie += "; Partitioned";
  }

  if (priority) {
    cookie += `; Priority=${priority}`;
  }

  return cookie;
}

/**
 * Creates a session cookie
 *
 * @param sessionToken - Session token value
 * @param config - Authentication configuration
 * @returns Cookie string for Set-Cookie header
 */
export function createSessionCookie(
  sessionToken: string,
  config: AegisAuthConfig,
): string {
  const { session } = config;
  const { name, ...cookieOptions } = session.cookie;

  return serializeCookie(name, sessionToken, {
    ...cookieOptions,
    partitioned: session.enhancedCookieOptions?.partitioned,
    priority: session.enhancedCookieOptions?.priority,
  });
}

/**
 * Creates a CSRF cookie
 *
 * @param csrfToken - CSRF token value
 * @param config - Authentication configuration
 * @returns Cookie string for Set-Cookie header
 */
export function createCsrfCookie(
  csrfToken: string,
  config: AegisAuthConfig,
): string {
  const { csrf } = config;
  const { name, ...cookieOptions } = csrf.cookie;

  return serializeCookie(name, csrfToken, {
    ...cookieOptions,
    partitioned: csrf.enhancedCookieOptions?.partitioned,
    priority: csrf.enhancedCookieOptions?.priority,
  });
}

/**
 * Creates a cookie to clear an existing cookie
 *
 * @param name - Cookie name to clear
 * @param options - Cookie options
 * @returns Cookie string that will clear the cookie
 */
export function createClearCookie(
  name: string,
  options: Omit<SerializeCookieOptions, "maxAgeSeconds">,
): string {
  return serializeCookie(name, "", {
    ...options,
    maxAgeSeconds: 0,
  });
}

/**
 * Clears the session cookie
 *
 * @param config - Authentication configuration
 * @returns Cookie string that will clear the session cookie
 */
export function clearSessionCookie(config: AegisAuthConfig): string {
  const { session } = config;
  const { name, ...cookieOptions } = session.cookie;

  return createClearCookie(name, {
    ...cookieOptions,
    partitioned: session.enhancedCookieOptions?.partitioned,
    priority: session.enhancedCookieOptions?.priority,
  });
}

/**
 * Clears the CSRF cookie
 *
 * @param config - Authentication configuration
 * @returns Cookie string that will clear the CSRF cookie
 */
export function clearCsrfCookie(config: AegisAuthConfig): string {
  const { csrf } = config;
  const { name, ...cookieOptions } = csrf.cookie;

  return createClearCookie(name, {
    ...cookieOptions,
    partitioned: csrf.enhancedCookieOptions?.partitioned,
    priority: csrf.enhancedCookieOptions?.priority,
  });
}

/**
 * Gets both session and CSRF cookies cleared
 *
 * @param config - Authentication configuration
 * @returns Object with both cookies cleared
 */
export function getClearAuthCookies(config: AegisAuthConfig): {
  sessionCookie: string;
  csrfCookie: string;
} {
  return {
    sessionCookie: clearSessionCookie(config),
    csrfCookie: clearCsrfCookie(config),
  };
}

/**
 * Parse cookies from a cookie header string
 *
 * @param cookieHeader - Cookie header string
 * @returns Parsed cookies as key-value pairs
 */
export function parseCookies(cookieHeader?: string): Record<string, string> {
  if (!cookieHeader) {
    return {};
  }

  return parseCookie(cookieHeader);
}

/**
 * Extract session token from request headers
 *
 * @param headers - Request headers
 * @param config - Authentication configuration
 * @returns Session token if found, undefined otherwise
 */
export function getSessionTokenFromHeaders(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  const cookieHeader = headers.get("cookie");
  const cookies = parseCookies(cookieHeader);

  return cookies[config.session.cookie.name];
}

/**
 * Extract CSRF token from request headers
 *
 * @param headers - Request headers
 * @param config - Authentication configuration
 * @returns CSRF token if found, undefined otherwise
 */
export function getCsrfTokenFromHeaders(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  // Try cookie first
  const cookieHeader = headers.get("cookie");
  const cookies = parseCookies(cookieHeader);
  const csrfCookie = cookies[config.csrf.cookie.name];

  if (csrfCookie) {
    return csrfCookie;
  }

  // Then check headers
  return (
    headers.get("x-csrf-token") ||
    headers.get("x-xsrf-token") ||
    headers.get("csrf-token")
  );
}
