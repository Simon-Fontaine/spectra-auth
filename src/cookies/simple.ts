import { serialize } from "cookie";

/**
 * Determines the session cookie name based on environment.
 */
function getCookieName(): string {
  return process.env.NODE_ENV === "production"
    ? "__Secure-spectra.session"
    : "spectra.session";
}

/**
 * Creates a session cookie with the given raw token and max age (in seconds).
 * Uses secure + httpOnly flags in production for better security.
 */
export function createSessionCookie(
  rawToken: string,
  maxAgeSeconds: number,
): string {
  return serialize(getCookieName(), rawToken, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: maxAgeSeconds,
  });
}

/**
 * Clears the session cookie by setting it to an empty string, with maxAge=0.
 */
export function clearSessionCookie(): string {
  return serialize(getCookieName(), "", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    path: "/",
    maxAge: 0,
  });
}

/**
 * Extracts the session token from the cookie header (if present).
 */
export function getSessionTokenFromHeader(
  cookieHeader: string | null,
): string | null {
  if (!cookieHeader) return null;
  const name = getCookieName();

  const cookies = cookieHeader.split(";").reduce(
    (acc, c) => {
      const [k, ...rest] = c.trim().split("=");
      acc[k] = rest.join("=");
      return acc;
    },
    {} as Record<string, string>,
  );

  return cookies[name] || null;
}
