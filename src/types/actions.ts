import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import type { Endpoints } from "./ratelimit";

export interface CoreContext {
  prisma: PrismaClient;
  config: AegisAuthConfig;
  endpoints: Endpoints;
  parsedRequest?: ParsedRequest;
}

export interface ParsedRequest {
  ipAddress?: string;
  csrfToken?: string;
  sessionToken?: string;
  deviceData?: {
    name?: string | null;
    type?: string | null;
    browser?: string | null;
    os?: string | null;
    userAgent?: string | null;
  };
  locationData?: {
    country?: string | null;
    region?: string | null;
    city?: string | null;
    latitude?: number | null;
    longitude?: number | null;
  };
  headers: Headers;
}
