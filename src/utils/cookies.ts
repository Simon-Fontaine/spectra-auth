import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import type { AegisAuthConfig } from "../types";

export function createSessionCookie(
  sessionToken: string,
  config: AegisAuthConfig,
) {
  const { name, ...cookieOptions } = config.security.session.cookie;

  return serializeCookie(name, sessionToken, cookieOptions);
}

export function clearSessionCookie(config: AegisAuthConfig) {
  const { name, ...cookieOptions } = config.security.session.cookie;

  return serializeCookie(name, "", {
    ...cookieOptions,
    maxAge: 0,
  });
}

export function getSessionToken(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  const cookie = headers.get("cookie");

  if (!cookie) return;

  const cookies = parseCookie(cookie);

  return cookies[config.security.session.cookie.name];
}

export function createCsrfCookie(csrfToken: string, config: AegisAuthConfig) {
  const { name, ...cookieOptions } = config.security.csrf.cookie;

  return serializeCookie(name, csrfToken, cookieOptions);
}

export function clearCsrfCookie(config: AegisAuthConfig) {
  const { name, ...cookieOptions } = config.security.csrf.cookie;

  return serializeCookie(name, "", {
    ...cookieOptions,
    maxAge: 0,
  });
}

export function getCsrfToken(headers: Headers, config: AegisAuthConfig) {
  const cookie = headers.get("cookie");

  if (!cookie) return;

  const cookies = parseCookie(cookie);

  return cookies[config.security.csrf.cookie.name];
}
