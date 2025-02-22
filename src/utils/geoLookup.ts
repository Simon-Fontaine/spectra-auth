import { WebServiceClient } from "@maxmind/geoip2-node";
import { UAParser } from "ua-parser-js";
import type { AegisAuthConfig } from "../types";
import type { SessionDevice, SessionLocation } from "../types";
import type { AegisResponse } from "../types";
import { fail, success } from "./response";

export async function geoLookup(
  config: AegisAuthConfig,
  ipAddress?: string,
  userAgent?: string,
): Promise<
  AegisResponse<{ locationData?: SessionLocation; deviceData?: SessionDevice }>
> {
  try {
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
      const client = new WebServiceClient(
        config.geoLookup.maxmindClientId,
        config.geoLookup.maxmindLicenseKey,
        { host: config.geoLookup.maxmindHost },
      );

      try {
        const response = await client.city(ipAddress);
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

    return success({ locationData, deviceData });
  } catch (error) {
    return fail("GEO_LOOKUP_ERROR", "Failed to retrieve location data");
  }
}
