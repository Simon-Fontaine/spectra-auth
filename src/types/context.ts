import type { Prisma, PrismaClient } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { EndpointName } from "../constants";
import type { AegisAuthConfig } from "./config";
import type { CsrfToken, SessionToken } from "./security";

/**
 * Rate limiter collection indexed by endpoint
 */
export type Endpoints = Partial<Record<EndpointName, Ratelimit>>;

/**
 * Type for Session with User and UserRoles included
 */
export type SessionWithRelations = Prisma.SessionGetPayload<{
  include: {
    user: {
      include: {
        userRoles: {
          include: {
            role: true;
          };
        };
      };
    };
  };
}>;

/**
 * Authenticated user information (safe to expose to application)
 */
export interface AuthenticatedUser {
  id: string;
  username: string;
  email: string;
  isEmailVerified: boolean;
  isBanned: boolean;
  createdAt: Date;
  updatedAt: Date;
  displayName?: string | null;
  avatarUrl?: string | null;
  roles: string[];
  permissions: string[];
}

/**
 * Authentication context that contains everything needed for auth operations
 */
export interface AegisContext {
  // Database access
  prisma: PrismaClient;

  // Configuration
  config: AegisAuthConfig;

  // Rate limiting
  endpoints: Endpoints;

  // Request data
  req: {
    ipAddress?: string;
    userAgent?: string;
    csrfToken?: CsrfToken;
    sessionToken?: SessionToken;
    headers: Headers;
  };

  // Authentication state
  auth: {
    isAuthenticated: boolean;
    user?: AuthenticatedUser | null;
    session?: SessionWithRelations | null;
  };
}

/**
 * Extended authentication context with cookies for responses
 */
export interface ResponseContext extends AegisContext {
  cookies?: {
    sessionCookie: string;
    csrfCookie: string;
  };
}
