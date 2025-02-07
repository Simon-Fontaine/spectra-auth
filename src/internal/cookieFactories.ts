import {
  clearSessionCookie,
  createSessionCookie,
  getSessionTokenFromHeaders,
} from "../cookies";
import type { SpectraAuthConfig } from "../types";

export function createSessionCookieFactory(
  config: Required<SpectraAuthConfig>,
) {
  return (rawToken: string, maxAgeSeconds: number) => {
    createSessionCookie(rawToken, maxAgeSeconds, config);
  };
}

export function clearSessionCookieFactory(config: Required<SpectraAuthConfig>) {
  return () => {
    clearSessionCookie(config);
  };
}

export function getSessionTokenFromHeadersFactory(
  config: Required<SpectraAuthConfig>,
) {
  return (cookieHeader: string | undefined) => {
    getSessionTokenFromHeaders(cookieHeader, config);
  };
}
