import type { PrismaClient } from "@prisma/client";
import { Ratelimit } from "@upstash/ratelimit";
import { logoutUserCore } from "./auth";
import { buildConfig } from "./config";
import {
  type AegisAuthConfig,
  type AegisContext,
  type Endpoints,
  defaultEndpoints,
} from "./types";
import { processRequest } from "./utils";

export class AegisAuth {
  private config: AegisAuthConfig;
  private prisma: PrismaClient;
  private endpoints: Endpoints = {};

  private async createContext(headers: Headers): Promise<AegisContext> {
    const response = await processRequest(
      this.prisma,
      this.config,
      this.endpoints,
      headers,
    );

    if (!response.success) {
      throw new Error(`Failed to create context: ${response.error.message}`);
    }

    return response.data;
  }

  private initializeEndpoints() {
    const { rateLimit } = this.config;
    if (!rateLimit.enabled || !rateLimit.redis) return;

    try {
      for (const endpoint of defaultEndpoints) {
        const endpointConfig = rateLimit.endpoints[endpoint];
        if (!endpointConfig || !endpointConfig.enabled) continue;
        this.endpoints[endpoint] = new Ratelimit({
          redis: rateLimit.redis,
          limiter: Ratelimit.slidingWindow(
            endpointConfig.maxRequests,
            `${endpointConfig.windowSeconds} s`,
          ),
          prefix: `${rateLimit.prefix}:${endpoint}`,
        });
      }
    } catch (error) {
      this.config.logger?.error("Failed to initialize endpoints.", {
        error: error instanceof Error ? error.message : String(error),
      });
    }
  }

  constructor(prisma: PrismaClient, userConfig?: Partial<AegisAuthConfig>) {
    this.prisma = prisma;

    const response = buildConfig(userConfig ?? {});
    if (!response.success) {
      throw new Error(`Failed to create config: ${response.error.message}`);
    }

    this.config = response.data;
    this.initializeEndpoints();
  }

  getConfig(): AegisAuthConfig {
    return this.config;
  }

  async logoutUser(headers: Headers) {
    const ctx = await this.createContext(headers);
    return logoutUserCore(ctx);
  }
}
