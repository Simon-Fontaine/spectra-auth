import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import type { PrismaSession, PrismaUser } from "./prisma";
import type { Endpoints } from "./ratelimit";

export interface AegisContext {
  prisma: PrismaClient;
  config: AegisAuthConfig;
  endpoints: Endpoints;
  parsedRequest?: ParsedRequest;
}

export interface ParsedRequest {
  session?: PrismaSession;
  user?: PrismaUser;
}
