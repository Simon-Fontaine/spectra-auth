import { WebServiceClient } from "@maxmind/geoip2-node";
import { UAParser } from "ua-parser-js";
import type { AegisAuthConfig } from "../config";
import type { ParsedRequest } from "../types";
import type { SessionDevice, SessionLocation } from "../types/prisma";
import { getCsrfToken, getSessionToken } from "./cookies";

export async function parseRequest(
  headers: Headers,
  config: AegisAuthConfig,
): Promise<ParsedRequest> {
  try {
    const userAgent = headers.get("user-agent") || "";
    const forwardedFor = headers.get("x-forwarded-for");
    const csrfToken = getCsrfToken(headers, config) || "";
    const sessionToken = getSessionToken(headers, config) || "";

    let ipAddress: string | undefined;
    let locationData: SessionLocation | undefined;
    let deviceData: SessionDevice | undefined;

    if (userAgent) {
      const parsedUserAgent = UAParser(userAgent);
      deviceData = {
        name: parsedUserAgent.device.vendor,
        type: parsedUserAgent.device.type,
        browser: parsedUserAgent.browser.name,
        os: parsedUserAgent.os.name,
        userAgent: parsedUserAgent.ua,
      };
    }

    if (forwardedFor) {
      const ips = Array.isArray(forwardedFor)
        ? forwardedFor
        : forwardedFor.split(",").map((ip) => ip.trim());
      ipAddress = ips[0];
    } else {
      ipAddress = headers.get("x-real-ip") || undefined;
    }

    if (ipAddress && config.auth.geo.enabled) {
      if (
        !config.auth.geo.maxmindClientId ||
        !config.auth.geo.maxmindLicenseKey
      ) {
        throw new Error(
          "Geo location is enabled but no MaxMind credentials provided",
        );
      }

      try {
        const response = await new WebServiceClient(
          config.auth.geo.maxmindClientId,
          config.auth.geo.maxmindLicenseKey,
          {
            host: config.auth.geo.maxmindHost,
          },
        ).city(ipAddress);

        const { country, city, subdivisions } = response;
        locationData = {
          country: country?.names.en,
          region: subdivisions?.at(-1)?.names.en,
          city: city?.names.en,
          latitude: response.location?.latitude,
          longitude: response.location?.longitude,
        };
      } catch (error) {
        config.logger?.error("Error fetching location data", {
          error: error instanceof Error ? error.message : String(error),
        });
      }
    }

    return {
      ipAddress,
      csrfToken,
      sessionToken,
      locationData,
      deviceData,
      headers,
    };
  } catch (error) {
    config.logger?.error("Error parsing request", {
      error: error instanceof Error ? error.message : String(error),
    });

    return {
      ipAddress: undefined,
      csrfToken: "",
      sessionToken: "",
      locationData: undefined,
      deviceData: undefined,
      headers: new Headers(),
    };
  }
}
