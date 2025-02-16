import type { PrismaClient } from "@prisma/client";
import { Ratelimit } from "@upstash/ratelimit";
import { buildConfig } from "./config";
import {
  type AegisAuthConfig,
  type CoreContext,
  type Endpoints,
  defaultEndpoints,
} from "./types";
import { parseRequest } from "./utils";

export class AegisAuth {
  private config: AegisAuthConfig;
  private prisma: PrismaClient;
  private endpoints: Endpoints = {};

  private async createContext(headers?: Headers): Promise<CoreContext> {
    const parsedRequest = headers
      ? await parseRequest(headers, this.config)
      : undefined;

    return {
      prisma: this.prisma,
      config: this.config,
      endpoints: this.endpoints,
      parsedRequest,
    };
  }

  private initializeEndpoints() {
    const { rateLimit } = this.config.protection;
    if (!rateLimit.enabled || !rateLimit.redis) return;

    for (const endpoint of defaultEndpoints) {
      const endpointConfig = rateLimit.endpoints[endpoint];
      if (!endpointConfig || !endpointConfig.enabled) continue;

      this.endpoints[endpoint] = new Ratelimit({
        redis: rateLimit.redis,
        limiter: Ratelimit.slidingWindow(
          endpointConfig.maxAttempts,
          `${endpointConfig.window} s`,
        ),
        prefix: `${rateLimit.prefix}:${endpoint}`,
      });
    }
  }

  constructor(prisma: PrismaClient, userConfig?: Partial<AegisAuthConfig>) {
    this.prisma = prisma;
    this.config = buildConfig(userConfig);
    this.initializeEndpoints();
  }

  getConfig() {
    return this.config;
  }
}
