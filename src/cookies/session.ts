import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import type { AegisAuthConfig } from "../config";

export function createSessionCookie({
  sessionToken,
  config,
}: { sessionToken: string; config: AegisAuthConfig }): string {
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
}: { config: AegisAuthConfig }): string {
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
}: { cookieHeader: string; config: AegisAuthConfig }): string | undefined {
  const sessionToken = parseCookie(cookieHeader)[config.session.cookieName];
  return sessionToken;
}
