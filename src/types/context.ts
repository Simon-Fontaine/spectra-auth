import type { PrismaClient } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { EndpointName } from "../constants";
import type { AegisAuthConfig } from "./config";

/**
 * Rate limiter collection indexed by endpoint
 */
export type Endpoints = Partial<Record<EndpointName, Ratelimit>>;

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
    csrfToken?: string;
    headers: Headers;
  };

  // Authentication state
  auth: {
    isAuthenticated: boolean;
    user?: AuthenticatedUser | null;
    session?: unknown | null; // Will use Prisma type
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
