import type { Prisma, PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../types";
import type { Endpoints } from "./rateLimit";

export interface AuthenticatedUser
  extends Omit<
    Prisma.UserGetPayload<{
      include: {
        userRoles: { include: { role: true } };
        sessions: true;
        passwordHistory: true;
      };
    }>,
    "passwordHash" | "userRoles" | "passwordHistory" | "sessions"
  > {
  roles: string[];
  permissions: string[];
  sessions: Prisma.SessionGetPayload<true>[];
  passwordHistory: Prisma.PasswordHistoryGetPayload<true>[];
}

export interface AegisContext {
  prisma: PrismaClient;
  config: AegisAuthConfig;
  endpoints: Endpoints;
  req: {
    ipAddress?: string;
    userAgent?: string;
    csrfToken?: string;
    headers: Headers;
  };
  auth: {
    isAuthenticated: boolean;
    user?: AuthenticatedUser | null;
    session?: Prisma.SessionGetPayload<true> | null;
  };
}
