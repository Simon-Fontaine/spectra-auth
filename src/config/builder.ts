import { merge } from "lodash";
import { ErrorCode } from "../constants";
import type { AegisAuthConfig, AegisResponse } from "../types";
import { fail, success } from "../utils/response";
import {
  defaultAccountConfig,
  defaultCoreConfig,
  defaultCsrfConfig,
  defaultEmailConfig,
  defaultGeoLookupConfig,
  defaultIPDetectionOptions,
  defaultLoginConfig,
  defaultPasswordConfig,
  defaultRateLimitConfig,
  defaultRegistrationConfig,
  defaultSessionConfig,
  defaultVerificationConfig,
} from "./defaults";
import { validateConfig } from "./validator";

/**
 * Builds a complete configuration by merging user-provided options with defaults
 *
 * @param userConfig - User-provided configuration options
 * @returns Response with complete configuration or error
 */
export function buildConfig(
  userConfig: Partial<AegisAuthConfig> = {},
): AegisResponse<AegisAuthConfig> {
  try {
    // Create default configuration
    const defaultConfig: AegisAuthConfig = {
      core: defaultCoreConfig,
      account: defaultAccountConfig,
      registration: defaultRegistrationConfig,
      login: defaultLoginConfig,
      password: defaultPasswordConfig,
      session: defaultSessionConfig,
      csrf: defaultCsrfConfig,
      verification: defaultVerificationConfig,
      rateLimit: defaultRateLimitConfig,
      geoLookup: defaultGeoLookupConfig,
      email: defaultEmailConfig,
      ipDetection: defaultIPDetectionOptions,
    };

    // Deep merge with user configuration
    const config = merge({}, defaultConfig, userConfig);

    for (const endpoint in config.rateLimit.endpoints) {
      if (
        !config.rateLimit.endpoints[
          endpoint as keyof typeof config.rateLimit.endpoints
        ]
      ) {
        config.rateLimit.endpoints[
          endpoint as keyof typeof config.rateLimit.endpoints
        ] =
          defaultRateLimitConfig.endpoints[
            endpoint as keyof typeof defaultRateLimitConfig.endpoints
          ];
      }
    }

    // Validate the complete configuration
    const validationResult = validateConfig(config);
    if (!validationResult.success) {
      return validationResult;
    }

    return success(config);
  } catch (error) {
    return fail(
      ErrorCode.CONFIG_ERROR,
      `Failed to build configuration: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}
