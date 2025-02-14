import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import type { ParsedRequestData } from "../utils";
import type { Limiters } from "./rateLimit";

export interface CoreContext {
  prisma: PrismaClient;
  config: AegisAuthConfig;
  limiters: Limiters;
  parsedRequest?: ParsedRequestData;
}
