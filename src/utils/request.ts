import { UAParser } from "ua-parser-js";
import type { AegisAuthConfig } from "../config";
import { getCsrfToken, getSessionToken } from "../cookies";

export function parseRequest({
  request,
  config,
}: {
  request: Request;
  config: Required<AegisAuthConfig>;
}) {
  const sessionHeader = request.headers.get(config.session.cookieName) || "";
  const csrfHeader = request.headers.get(config.csrf.cookieName) || "";

  const sessionToken = getSessionToken({ cookieHeader: sessionHeader, config });
  const csrfToken = getCsrfToken({ cookieHeader: csrfHeader, config });

  const userAgent = request.headers.get("user-agent");
  const { ua, device, browser, os } = UAParser(userAgent);

  let ipAddress: string | null = null;
  const forwardedFor = request.headers.get("x-forwarded-for") as
    | string[]
    | string
    | null;

  if (forwardedFor) {
    const ips = Array.isArray(forwardedFor) ? forwardedFor[0] : forwardedFor;
    ipAddress = ips.split(",")[0].trim();
  } else {
    ipAddress = request.headers.get("x-real-ip");
  }

  return {
    sessionToken,
    csrfToken,
    userAgent: ua,
    device: device.type ?? "Desktop",
    browser: browser.name ?? "Unknown",
    os: os.name ?? "Unknown",
    ipAddress,
  };
}
