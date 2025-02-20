import { WebServiceClient } from "@maxmind/geoip2-node";
import { UAParser } from "ua-parser-js";
import type { AegisAuthConfig } from "../config";
import type { SessionDevice, SessionLocation } from "../types";

export async function geoLookup(
  config: AegisAuthConfig,
  ipAddress?: string,
  userAgent?: string,
): Promise<{ locationData?: SessionLocation; deviceData?: SessionDevice }> {
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

  if (ipAddress && config.geoLookup.enabled) {
    try {
      const response = await new WebServiceClient(
        config.geoLookup.maxmindClientId,
        config.geoLookup.maxmindLicenseKey,
        {
          host: config.geoLookup.maxmindHost,
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

  return { locationData, deviceData };
}
