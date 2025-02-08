import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import type { SpectraAuthConfig } from "../config";

export function createCsrfCookie({
  csrfToken,
  config,
}: { csrfToken: string; config: Required<SpectraAuthConfig> }): string {
  return serializeCookie(config.csrf.cookieName, csrfToken, {
    maxAge: config.csrf.maxAgeSeconds,
    secure: config.csrf.cookieSecure,
    httpOnly: config.csrf.cookieHttpOnly,
    sameSite: config.csrf.cookieSameSite,
    path: "/",
  });
}

export function clearCsrfCookie({
  config,
}: { config: Required<SpectraAuthConfig> }): string {
  return serializeCookie(config.csrf.cookieName, "", {
    maxAge: 0,
    secure: config.csrf.cookieSecure,
    httpOnly: config.csrf.cookieHttpOnly,
    sameSite: config.csrf.cookieSameSite,
  });
}

export function getCsrfToken({
  cookieHeader,
  config,
}: { cookieHeader: string; config: Required<SpectraAuthConfig> }):
  | string
  | undefined {
  const csrfToken = parseCookie(cookieHeader)[config.csrf.cookieName];
  return csrfToken;
}
