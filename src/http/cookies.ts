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
 * Maximum cookie size recommended by browsers (in bytes)
 */
const MAX_COOKIE_SIZE = 4096;

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
 * Extracts the appropriate domain for cookies based on the hostname
 *
 * @param host - The request host (e.g., "app.example.com")
 * @param useRootDomain - Whether to use the root domain instead of the full hostname
 * @returns The appropriate domain value or undefined for localhost
 */
export function getDomainFromHost(
  host: string,
  useRootDomain = false,
): string | undefined {
  if (!host || host === "localhost" || host.includes("127.0.0.1")) {
    return undefined;
  }

  // Remove port if present
  const hostWithoutPort = host.split(":")[0];

  const parts = hostWithoutPort.split(".");
  if (parts.length <= 1) {
    return undefined;
  }

  // For root domain usage (e.g., example.com instead of subdomain.example.com)
  if (useRootDomain && parts.length > 2) {
    const rootDomain = parts.slice(-2).join(".");
    // Only return root domain if it's not an IP address
    return /^\d+\.\d+$/.test(rootDomain) ? undefined : rootDomain;
  }

  return hostWithoutPort;
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

  // Add explicit Expires date for better compatibility
  const expires = maxAgeSeconds
    ? new Date(Date.now() + maxAgeSeconds * 1000)
    : undefined;

  let cookie = serialize(name, value, {
    maxAge: maxAgeSeconds,
    expires,
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

  // Check cookie size and warn if it exceeds the limit
  if (cookie.length > MAX_COOKIE_SIZE) {
    console.warn(
      `Cookie ${name} exceeds ${MAX_COOKIE_SIZE} bytes and may be truncated by browsers`,
    );
  }

  return cookie;
}

/**
 * Creates a session cookie.
 *
 * @param sessionToken - Session token value
 * @param config - Authentication configuration
 * @param host - Optional host for domain detection
 * @returns Cookie string for Set-Cookie header
 */
export function createSessionCookie(
  sessionToken: string,
  config: AegisAuthConfig,
  host?: string,
): string {
  const { session } = config;
  const { name, ...cookieOptions } = session.cookie;

  // If domain isn't explicitly set but host is provided, try to determine domain
  const options = { ...cookieOptions };
  if (!options.domain && host) {
    options.domain = getDomainFromHost(host, true); // Use root domain for session cookies
  }

  return serializeCookie(
    name,
    sessionToken,
    getFullCookieOptions(options, session.enhancedCookieOptions),
  );
}

/**
 * Creates a CSRF cookie.
 *
 * @param csrfToken - CSRF token value
 * @param config - Authentication configuration
 * @param host - Optional host for domain detection
 * @returns Cookie string for Set-Cookie header
 */
export function createCsrfCookie(
  csrfToken: string,
  config: AegisAuthConfig,
  host?: string,
): string {
  const { csrf } = config;
  const { name, ...cookieOptions } = csrf.cookie;

  // If domain isn't explicitly set but host is provided, try to determine domain
  const options = { ...cookieOptions };
  if (!options.domain && host) {
    options.domain = getDomainFromHost(host, true); // Use root domain for CSRF cookies
  }

  return serializeCookie(
    name,
    csrfToken,
    getFullCookieOptions(options, csrf.enhancedCookieOptions),
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
 * @param host - Optional host for domain detection
 * @returns Cookie string that will clear the session cookie
 */
export function clearSessionCookie(
  config: AegisAuthConfig,
  host?: string,
): string {
  const { session } = config;
  const { name, ...cookieOptions } = session.cookie;

  // If domain isn't explicitly set but host is provided, try to determine domain
  const options = { ...cookieOptions };
  if (!options.domain && host) {
    options.domain = getDomainFromHost(host, true); // Use root domain for session cookies
  }

  return createClearCookie(
    name,
    getFullCookieOptions(options, session.enhancedCookieOptions),
  );
}

/**
 * Clears the CSRF cookie.
 *
 * @param config - Authentication configuration
 * @param host - Optional host for domain detection
 * @returns Cookie string that will clear the CSRF cookie
 */
export function clearCsrfCookie(
  config: AegisAuthConfig,
  host?: string,
): string {
  const { csrf } = config;
  const { name, ...cookieOptions } = csrf.cookie;

  // If domain isn't explicitly set but host is provided, try to determine domain
  const options = { ...cookieOptions };
  if (!options.domain && host) {
    options.domain = getDomainFromHost(host, true); // Use root domain for CSRF cookies
  }

  return createClearCookie(
    name,
    getFullCookieOptions(options, csrf.enhancedCookieOptions),
  );
}

/**
 * Returns both session and CSRF cookies cleared.
 *
 * @param config - Authentication configuration
 * @param host - Optional host for domain detection
 * @returns Object with both cookies cleared
 */
export function getClearAuthCookies(
  config: AegisAuthConfig,
  host?: string,
): {
  sessionCookie: string;
  csrfCookie: string;
} {
  return {
    sessionCookie: clearSessionCookie(config, host),
    csrfCookie: clearCsrfCookie(config, host),
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
