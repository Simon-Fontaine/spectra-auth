import type { AegisAuthConfig } from "../types";

export interface IPDetectionOptions {
  trustProxyHeaders: boolean;
  proxyHeaderPrecedence: string[];
  allowPrivateIPs: boolean;
}

const DEFAULT_IP_DETECTION_OPTIONS: IPDetectionOptions = {
  trustProxyHeaders: true,
  proxyHeaderPrecedence: [
    "x-forwarded-for",
    "x-real-ip",
    "cf-connecting-ip",
    "true-client-ip",
    "x-client-ip",
    "forwarded",
  ],
  allowPrivateIPs: false,
};

const PRIVATE_IP_RANGES = [
  // IPv4 private ranges
  { regex: /^0\./, note: "Current network" },
  { regex: /^10\./, note: "Class A private" },
  { regex: /^127\./, note: "Loopback" },
  { regex: /^169\.254\./, note: "Link-local" },
  { regex: /^172\.(1[6-9]|2[0-9]|3[0-1])\./, note: "Class B private" },
  { regex: /^192\.168\./, note: "Class C private" },
  // IPv6 private ranges (simplified)
  { regex: /^::1$/, note: "Loopback" },
  { regex: /^f[cd]/, note: "Unique local" },
  { regex: /^fe80:/, note: "Link-local" },
];

function isPrivateIP(ip: string): boolean {
  return PRIVATE_IP_RANGES.some((range) => range.regex.test(ip));
}

export function extractClientIP(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  const options = config.ipDetection || DEFAULT_IP_DETECTION_OPTIONS;

  if (!options.trustProxyHeaders) {
    return undefined;
  }

  for (const header of options.proxyHeaderPrecedence) {
    const headerValue = headers.get(header);

    if (!headerValue) continue;

    if (header.toLowerCase() === "x-forwarded-for") {
      const ips = headerValue.split(",").map((ip) => ip.trim());
      for (const ip of ips) {
        if (!isPrivateIP(ip) || options.allowPrivateIPs) {
          return ip;
        }
      }
      if (options.allowPrivateIPs && ips.length > 0) {
        return ips[0];
      }
    } else if (header.toLowerCase() === "forwarded") {
      const forwardedHeader = headerValue;
      const forParts = forwardedHeader.split(";").map((s) => s.trim());

      for (const part of forParts) {
        if (part.startsWith("for=")) {
          let ip = part.substring(4);
          ip = ip.replace(/["[\]]/g, "");
          if (!isPrivateIP(ip) || options.allowPrivateIPs) {
            return ip;
          }
        }
      }
    } else {
      const ip = headerValue.trim();
      if (!isPrivateIP(ip) || options.allowPrivateIPs) {
        return ip;
      }
    }
  }

  return undefined;
}
