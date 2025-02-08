import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import type { SpectraAuthConfig } from "../config";

export function createSessionCookie({
  sessionToken,
  config,
}: { sessionToken: string; config: Required<SpectraAuthConfig> }): string {
  return serializeCookie(config.session.cookieName, sessionToken, {
    maxAge: config.session.maxAgeSeconds,
    secure: config.session.cookieSecure,
    httpOnly: config.session.cookieHttpOnly,
    sameSite: config.session.cookieSameSite,
    path: "/",
  });
}

export function clearSessionCookie({
  config,
}: { config: Required<SpectraAuthConfig> }): string {
  return serializeCookie(config.session.cookieName, "", {
    maxAge: 0,
    secure: config.session.cookieSecure,
    httpOnly: config.session.cookieHttpOnly,
    sameSite: config.session.cookieSameSite,
  });
}

export function getSessionToken({
  cookieHeader,
  config,
}: { cookieHeader: string; config: Required<SpectraAuthConfig> }):
  | string
  | undefined {
  const sessionToken = parseCookie(cookieHeader)[config.session.cookieName];
  return sessionToken;
}
