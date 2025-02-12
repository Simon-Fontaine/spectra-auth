import { UAParser } from "ua-parser-js";
import type { AegisAuthConfig } from "../config";
import { getCsrfToken, getSessionToken } from "../cookies";
import type { AuthHeaders } from "../types";

export interface ParsedRequestData {
  sessionToken?: string;
  csrfToken?: string;
  userAgent?: string;
  device: string;
  browser: string;
  os: string;
  ipAddress?: string;
}

export function parseRequest(
  request: {
    headers: AuthHeaders;
  },
  config: AegisAuthConfig,
): ParsedRequestData {
  const getHeader = (key: string) => {
    if ("get" in request.headers && typeof request.headers.get === "function") {
      return request.headers.get(key);
    }
    return undefined;
  };

  const sessionHeader = getHeader(config.session.cookieName) || "";
  const csrfHeader = getHeader(config.csrf.cookieName) || "";

  const sessionToken = getSessionToken({
    cookieHeader: sessionHeader,
    config,
  });
  const csrfToken = getCsrfToken({ cookieHeader: csrfHeader, config });

  const userAgent = getHeader("user-agent");
  const { ua, device, browser, os } = UAParser(userAgent);

  let ipAddress: string | undefined = undefined;
  const forwardedFor = getHeader("x-forwarded-for");

  if (forwardedFor) {
    const ips = Array.isArray(forwardedFor)
      ? forwardedFor[0]
      : forwardedFor.split(",")[0];
    ipAddress = ips.trim();
  } else {
    ipAddress = getHeader("x-real-ip") ?? undefined;
  }

  return {
    sessionToken,
    csrfToken,
    userAgent: ua,
    device: device.type ?? "Desktop",
    browser: browser.name ?? "Unknown",
    os: os.name ?? "Unknown",
    ipAddress: ipAddress,
  };
}
