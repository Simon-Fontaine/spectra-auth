import { serialize } from "cookie";

/**
 * Determines the session cookie name based on the environment.
 *
 * @returns The appropriate cookie name for the session.
 */
function getCookieName(): string {
  return process.env.NODE_ENV === "production"
    ? "__Secure-spectra.session"
    : "spectra.session";
}

/**
 * Creates a session cookie with the given raw token and maximum age.
 *
 * - Uses secure and httpOnly flags in production for better security.
 *
 * @param rawToken - The session token to store.
 * @param maxAgeSeconds - The duration (in seconds) the cookie should be valid.
 * @returns A serialized session cookie.
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
 * Clears the session cookie by setting its value to an empty string and maxAge to 0.
 *
 * @returns A serialized cookie that will clear the session.
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
 * Extracts the session token from the cookie header if present.
 *
 * @param cookieHeader - The raw cookie header from the request.
 * @returns The session token or null if not found.
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
