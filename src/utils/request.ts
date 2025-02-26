import type { PrismaClient } from "@prisma/client";
import type {
  AegisAuthConfig,
  AegisContext,
  AuthenticatedUser,
  Endpoints,
} from "../types";
import { getCsrfToken, getSessionToken } from "./cookies";
import { extractClientIP } from "./ip";

/**
 * Extract key information from request headers
 *
 * @param headers - Request headers
 * @param config - Auth configuration
 * @returns Object with extracted request information
 */
export function parseRequest(
  headers: Headers,
  config: AegisAuthConfig,
): {
  ipAddress?: string;
  userAgent?: string;
  csrfToken?: string;
  sessionToken?: string;
} {
  return {
    ipAddress: extractClientIP(headers, config),
    userAgent: headers.get("user-agent") || undefined,
    csrfToken: config.csrf.enabled ? getCsrfToken(headers, config) : undefined,
    sessionToken: getSessionToken(headers, config),
  };
}

/**
 * Creates a basic unauthenticated context
 *
 * @param prisma - Prisma client
 * @param config - Auth configuration
 * @param endpoints - Rate limiting endpoints
 * @param headers - Request headers
 * @returns An unauthenticated context
 */
export function createContext(
  prisma: PrismaClient,
  config: AegisAuthConfig,
  endpoints: Endpoints,
  headers: Headers,
): AegisContext {
  const { ipAddress, userAgent, csrfToken, sessionToken } = parseRequest(
    headers,
    config,
  );

  return {
    prisma,
    config,
    endpoints,
    req: {
      ipAddress,
      userAgent,
      csrfToken,
      headers,
    },
    auth: {
      isAuthenticated: false,
      user: null,
      session: null,
    },
  };
}

/**
 * Creates an authenticated context from an existing context and session data
 *
 * @param context - Base context
 * @param user - Authenticated user
 * @param session - User session
 * @returns An authenticated context
 */
export function createAuthenticatedContext(
  context: AegisContext,
  user: AuthenticatedUser,
  session: unknown, // Session type would be more specific
): AegisContext {
  return {
    ...context,
    auth: {
      isAuthenticated: true,
      user,
      session,
    },
  };
}
