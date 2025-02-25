import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import type { AegisAuthConfig, EnhancedCookieOptions } from "../types";

export function createEnhancedCookie(
  name: string,
  value: string,
  options: EnhancedCookieOptions,
): string {
  const { partitioned, priority, ...standardOptions } = options;

  let cookie = serializeCookie(name, value, standardOptions);
  if (partitioned) {
    cookie += "; Partitioned";
  }

  if (priority) {
    cookie += `; Priority=${priority}`;
  }

  return cookie;
}

export function createSessionCookie(
  sessionToken: string,
  config: AegisAuthConfig,
): string {
  const { name, ...cookieOptions } = config.session.cookie;

  const enhancedOptions = {
    ...cookieOptions,
    partitioned: config.session.enhancedCookieOptions?.partitioned,
    priority: config.session.enhancedCookieOptions?.priority || "high",
  };

  return createEnhancedCookie(name, sessionToken, enhancedOptions);
}

export function clearSessionCookie(config: AegisAuthConfig): string {
  const { name, ...cookieOptions } = config.session.cookie;

  const enhancedOptions = {
    ...cookieOptions,
    maxAge: 0,
    partitioned: config.session.enhancedCookieOptions?.partitioned,
  };

  return createEnhancedCookie(name, "", enhancedOptions);
}

export function createCsrfCookie(
  csrfToken: string,
  config: AegisAuthConfig,
): string {
  const { name, ...cookieOptions } = config.csrf.cookie;

  const enhancedOptions = {
    ...cookieOptions,
    partitioned: config.csrf.enhancedCookieOptions?.partitioned,
    priority: config.csrf.enhancedCookieOptions?.priority || "medium",
  };

  return createEnhancedCookie(name, csrfToken, enhancedOptions);
}

export function clearCsrfCookie(config: AegisAuthConfig): string {
  const { name, ...cookieOptions } = config.csrf.cookie;

  const enhancedOptions = {
    ...cookieOptions,
    maxAge: 0,
    partitioned: config.csrf.enhancedCookieOptions?.partitioned,
  };

  return createEnhancedCookie(name, "", enhancedOptions);
}

export function getSessionToken(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  const cookie = headers.get("cookie");
  if (!cookie) return undefined;

  const cookies = parseCookie(cookie);
  return cookies[config.session.cookie.name];
}

export function getCsrfToken(headers: Headers, config: AegisAuthConfig) {
  const cookie = headers.get("cookie");
  if (!cookie) return undefined;

  const cookies = parseCookie(cookie);
  return cookies[config.csrf.cookie.name];
}
