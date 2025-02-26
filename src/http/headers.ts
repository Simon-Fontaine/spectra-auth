import { ErrorCode, RegexPatterns } from "../constants";
import type { AegisResponse, IPDetectionOptions } from "../types";
import { fail, success } from "../utils/response";

/**
 * Default headers for cross-origin protection
 */
export const securityHeaders = {
  "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY",
  "X-XSS-Protection": "1; mode=block",
  "Referrer-Policy": "strict-origin-when-cross-origin",
  "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
  "Content-Security-Policy": "default-src 'self';",
};

/**
 * Extracts client IP address from request headers
 *
 * @param headers - Request headers
 * @param options - IP detection options
 * @returns Response with the client IP or error
 */
export function extractClientIP(
  headers: Headers,
  options: IPDetectionOptions,
): AegisResponse<string | undefined> {
  try {
    // Skip if proxy headers are not trusted
    if (!options.trustProxyHeaders) {
      return success(undefined);
    }

    // Try each proxy header in priority order
    for (const headerName of options.proxyHeaderPrecedence) {
      const headerValue = headers.get(headerName.toLowerCase());
      if (!headerValue) continue;

      // Special case: X-Forwarded-For can contain multiple IPs
      if (headerName.toLowerCase() === "x-forwarded-for") {
        const ips = headerValue.split(",").map((ip) => ip.trim());

        // Use the first non-private IP or the first IP if private IPs are allowed
        for (const ip of ips) {
          if (!isPrivateIP(ip) || options.allowPrivateIPs) {
            return success(ip);
          }
        }

        // Use first IP if allowing private IPs
        if (options.allowPrivateIPs && ips.length > 0) {
          return success(ips[0]);
        }
      }
      // Special case: Forwarded header (RFC 7239)
      else if (headerName.toLowerCase() === "forwarded") {
        const forwardedParts = headerValue.split(";").map((s) => s.trim());

        // Extract the 'for' parameter
        for (const part of forwardedParts) {
          if (part.startsWith("for=")) {
            let ip = part.substring(4);
            // Remove quotes and brackets if present
            ip = ip.replace(/["[\]]/g, "");

            if (!isPrivateIP(ip) || options.allowPrivateIPs) {
              return success(ip);
            }
          }
        }
      }
      // Standard case: single IP in header
      else {
        const ip = headerValue.trim();
        if (!isPrivateIP(ip) || options.allowPrivateIPs) {
          return success(ip);
        }
      }
    }

    return success(undefined);
  } catch (error) {
    return fail(
      ErrorCode.GENERAL_ERROR,
      `Failed to extract client IP: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Checks if an IP address is private
 *
 * @param ip - IP address to check
 * @returns True if IP is private
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
 * Normalizes an IP address for consistent storage and comparison
 *
 * @param ip - IP address to normalize
 * @returns Normalized IP address
 */
export function normalizeIP(ip: string): string {
  // Handle IPv6 addresses
  if (ip.includes(":")) {
    // Remove leading zeros and normalize representation
    return ip.replace(/\b0+([0-9a-f]+)\b/g, "$1").toLowerCase();
  }

  // Handle IPv4 addresses
  if (ip.includes(".")) {
    // Remove leading zeros in each octet
    return ip.replace(/\b0+(\d+)\b/g, "$1");
  }

  return ip;
}

/**
 * Mask an IP address for privacy and logging
 *
 * @param ip - IP address to mask
 * @returns Masked IP address
 */
export function maskIP(ip: string): string {
  // IPv4 addresses: mask the last octet
  if (ip.includes(".")) {
    const parts = ip.split(".");
    return `${parts[0]}.${parts[1]}.${parts[2]}.*`;
  }

  // IPv6 addresses: mask the last 3 segments
  if (ip.includes(":")) {
    const parts = ip.split(":");
    return `${parts.slice(0, 5).join(":")}:***`;
  }

  return ip;
}
