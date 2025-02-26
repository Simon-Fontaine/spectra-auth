import { RegexPatterns } from "../constants";
import type { AegisAuthConfig } from "../types";

/**
 * IP detection options with defaults
 */
const DEFAULT_IP_DETECTION_OPTIONS = {
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

/**
 * Checks if an IP address is private
 *
 * @param ip - IP address to check
 * @returns True if the IP is private
 */
export function isPrivateIP(ip: string): boolean {
  // Check IPv4 private ranges
  const isPrivateIPv4 = RegexPatterns.IPV4_PRIVATE.some((pattern) =>
    pattern.test(ip),
  );

  if (isPrivateIPv4) return true;

  // Check IPv6 private ranges
  const isPrivateIPv6 = RegexPatterns.IPV6_PRIVATE.some((pattern) =>
    pattern.test(ip),
  );

  return isPrivateIPv6;
}

/**
 * Extract client IP from request headers based on configuration
 *
 * @param headers - Request headers
 * @param config - Auth configuration
 * @returns Client IP address or undefined
 */
export function extractClientIP(
  headers: Headers,
  config: AegisAuthConfig,
): string | undefined {
  const options = config.ipDetection || DEFAULT_IP_DETECTION_OPTIONS;

  // Skip if proxy headers are not trusted
  if (!options.trustProxyHeaders) {
    return undefined;
  }

  // Try each header in precedence order
  for (const header of options.proxyHeaderPrecedence) {
    const headerValue = headers.get(header.toLowerCase());
    if (!headerValue) continue;

    // Special handling for x-forwarded-for which can contain multiple IPs
    if (header.toLowerCase() === "x-forwarded-for") {
      const ips = headerValue.split(",").map((ip) => ip.trim());

      for (const ip of ips) {
        if (!isPrivateIP(ip) || options.allowPrivateIPs) {
          return ip;
        }
      }

      // Return first IP if allowing private IPs and no public IPs found
      if (options.allowPrivateIPs && ips.length > 0) {
        return ips[0];
      }
    }
    // Special handling for forwarded header (RFC 7239)
    else if (header.toLowerCase() === "forwarded") {
      const forwardedParts = headerValue.split(";").map((s) => s.trim());

      for (const part of forwardedParts) {
        if (part.startsWith("for=")) {
          let ip = part.substring(4);
          // Remove quotes and brackets if present
          ip = ip.replace(/["[\]]/g, "");

          if (!isPrivateIP(ip) || options.allowPrivateIPs) {
            return ip;
          }
        }
      }
    }
    // Regular header with single IP
    else {
      const ip = headerValue.trim();
      if (!isPrivateIP(ip) || options.allowPrivateIPs) {
        return ip;
      }
    }
  }

  return undefined;
}

/**
 * Normalize an IP address for comparison
 *
 * @param ip - IP address to normalize
 * @returns Normalized IP address
 */
export function normalizeIP(ip: string): string {
  // Handle IPv6 addresses
  if (ip.includes(":")) {
    // Remove leading zeros in each segment
    return ip.replace(/\b0+([0-9a-f]+)\b/g, "$1");
  }

  // Handle IPv4 addresses
  if (ip.includes(".")) {
    // Remove leading zeros in each octet
    return ip.replace(/\b0+(\d+)\b/g, "$1");
  }

  return ip;
}

/**
 * Masks an IP address for privacy
 *
 * @param ip - IP address to mask
 * @returns Masked IP address
 */
export function maskIP(ip: string): string {
  // For IPv4, mask the last octet
  if (ip.includes(".")) {
    const parts = ip.split(".");
    return `${parts[0]}.${parts[1]}.${parts[2]}.*`;
  }

  // For IPv6, mask the last 3 segments
  if (ip.includes(":")) {
    const parts = ip.split(":");
    return `${parts.slice(0, 5).join(":")}:***`;
  }

  return ip;
}
