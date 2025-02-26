import { parse, serialize } from "cookie";
import type { AegisAuthConfig, CookieOptions } from "../types";

/**
 * Enhanced cookie options with modern browser features.
 */
export interface SerializeCookieOptions extends Omit<CookieOptions, "name"> {
  partitioned?: boolean;
  priority?: "low" | "medium" | "high";
}

/**
 * Converts config cookie options to serialization options
 *
 * @param options - Base cookie options
 * @param enhancedOptions - Enhanced cookie options
 * @returns Complete serialization options
 */
function getFullCookieOptions(
  options: Omit<SerializeCookieOptions, "partitioned" | "priority">,
  enhancedOptions?: {
    partitioned?: boolean;
    priority?: "low" | "medium" | "high";
  },
): SerializeCookieOptions {
  return {
    ...options,
    partitioned: enhancedOptions?.partitioned,
    priority: enhancedOptions?.priority,
  };
}

/**
 * Serializes a cookie with both standard and enhanced options.
 * Defaults sameSite to "lax" if not provided.
 *
 * @param name - Cookie name
 * @param value - Cookie value
 * @param options - Cookie options
 * @returns Cookie string for the Set-Cookie header
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

  // Convert boolean/undefined sameSite to string values expected by cookie library
  const computedSameSite =
    sameSite === undefined
      ? "lax"
      : sameSite === true
        ? "strict"
        : sameSite === false
          ? "none"
          : sameSite;

  let cookie = serialize(name, value, {
    maxAge: maxAgeSeconds,
    httpOnly,
    secure,
    path,
    domain,
    sameSite: computedSameSite,
  });

  // Append modern cookie attributes
  if (partitioned) {
    cookie += "; Partitioned";
  }
  if (priority) {
    cookie += `; Priority=${priority}`;
  }
  return cookie;
}

/**
 * Creates a session cookie.
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

  return serializeCookie(
    name,
    sessionToken,
    getFullCookieOptions(cookieOptions, session.enhancedCookieOptions),
  );
}

/**
 * Creates a CSRF cookie.
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

  return serializeCookie(
    name,
    csrfToken,
    getFullCookieOptions(cookieOptions, csrf.enhancedCookieOptions),
  );
}

/**
 * Creates a cookie string that clears an existing cookie.
 *
 * @param name - Cookie name to clear
 * @param options - Cookie options without maxAgeSeconds
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
 * Clears the session cookie.
 *
 * @param config - Authentication configuration
 * @returns Cookie string that will clear the session cookie
 */
export function clearSessionCookie(config: AegisAuthConfig): string {
  const { session } = config;
  const { name, ...cookieOptions } = session.cookie;

  return createClearCookie(
    name,
    getFullCookieOptions(cookieOptions, session.enhancedCookieOptions),
  );
}

/**
 * Clears the CSRF cookie.
 *
 * @param config - Authentication configuration
 * @returns Cookie string that will clear the CSRF cookie
 */
export function clearCsrfCookie(config: AegisAuthConfig): string {
  const { csrf } = config;
  const { name, ...cookieOptions } = csrf.cookie;

  return createClearCookie(
    name,
    getFullCookieOptions(cookieOptions, csrf.enhancedCookieOptions),
  );
}

/**
 * Returns both session and CSRF cookies cleared.
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
 * Parses cookies from a cookie header string.
 *
 * @param cookieHeader - Cookie header string
 * @returns Parsed cookies as key-value pairs
 */
export function parseCookies(cookieHeader?: string): Record<string, string> {
  if (!cookieHeader) {
    return {};
  }

  // Parse cookies and filter out undefined values
  const parsed = parse(cookieHeader);
  return Object.fromEntries(
    Object.entries(parsed)
      .filter(([, value]) => value !== undefined)
      .map(([key, value]) => [key, value as string]),
  );
}

/**
 * Extracts the session token from request headers.
 *
 * @param headers - Request headers
 * @param config - Authentication configuration
 * @returns Session token if found, otherwise undefined
 */
export function getSessionTokenFromHeaders(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  const cookieHeader = headers.get("cookie") || undefined;
  const cookies = parseCookies(cookieHeader);
  return cookies[config.session.cookie.name];
}

/**
 * Extracts the CSRF token from request headers.
 * Checks cookie first, then various header locations.
 *
 * @param headers - Request headers
 * @param config - Authentication configuration
 * @returns CSRF token if found, otherwise undefined
 */
export function getCsrfTokenFromHeaders(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  const cookieHeader = headers.get("cookie") || undefined;
  const cookies = parseCookies(cookieHeader);
  const csrfCookie = cookies[config.csrf.cookie.name];

  if (csrfCookie) {
    return csrfCookie;
  }

  // Check common CSRF header locations
  const csrfHeaders = ["x-csrf-token", "x-xsrf-token", "csrf-token"];

  for (const header of csrfHeaders) {
    const value = headers.get(header);
    if (value) return value;
  }

  return undefined;
}
