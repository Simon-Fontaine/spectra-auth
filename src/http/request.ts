import type { PrismaClient } from "@prisma/client";
import { ErrorCode } from "../constants";
import { validateSession } from "../security/session";
import type {
  AegisAuthConfig,
  AegisContext,
  AegisResponse,
  AuthenticatedUser,
  CsrfToken,
  Endpoints,
  SessionToken,
  SessionWithRelations,
} from "../types";
import { createOperation } from "../utils/error";
import { fail, success } from "../utils/response";
import { getCsrfTokenFromHeaders, getSessionTokenFromHeaders } from "./cookies";
import { extractClientIP } from "./headers";

/**
 * Extracts authentication information from request headers
 *
 * @param headers - Request headers
 * @param config - Authentication configuration
 * @returns Response with extracted auth information
 */
export function parseRequestAuth(
  headers: Headers,
  config: AegisAuthConfig,
): AegisResponse<{
  ipAddress?: string;
  userAgent?: string;
  csrfToken?: CsrfToken;
  sessionToken?: SessionToken;
}> {
  try {
    // Extract IP address
    const ipResult = extractClientIP(
      headers,
      config.ipDetection || {
        trustProxyHeaders: false,
        proxyHeaderPrecedence: [],
        allowPrivateIPs: false,
      },
    );
    if (!ipResult.success) {
      return ipResult;
    }

    // Extract other data
    const userAgent = headers.get("user-agent") || undefined;
    const csrfToken = config.csrf.enabled
      ? (getCsrfTokenFromHeaders(headers, config) as CsrfToken)
      : undefined;
    const sessionToken = getSessionTokenFromHeaders(
      headers,
      config,
    ) as SessionToken;

    return success({
      ipAddress: ipResult.data,
      userAgent,
      csrfToken,
      sessionToken,
    });
  } catch (error) {
    return fail(
      ErrorCode.GENERAL_ERROR,
      `Failed to parse request: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Creates a base unauthenticated context
 *
 * @param prisma - Prisma client instance
 * @param config - Authentication configuration
 * @param endpoints - Rate limiters by endpoint
 * @param headers - Request headers
 * @returns Response with unauthenticated context
 */
export function createBaseContext(
  prisma: PrismaClient,
  config: AegisAuthConfig,
  endpoints: Endpoints,
  headers: Headers,
): AegisResponse<AegisContext> {
  try {
    const authResult = parseRequestAuth(headers, config);
    if (!authResult.success) {
      return authResult;
    }

    const { ipAddress, userAgent, csrfToken, sessionToken } = authResult.data;

    return success({
      prisma,
      config,
      endpoints,
      req: {
        ipAddress,
        userAgent,
        csrfToken,
        sessionToken,
        headers,
      },
      auth: {
        isAuthenticated: false,
        user: null,
        session: null,
      },
    });
  } catch (error) {
    return fail(
      ErrorCode.GENERAL_ERROR,
      `Failed to create base context: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/**
 * Converts user and session records to an authenticated user object
 *
 * @param session - Session with user relations
 * @returns Authenticated user object
 */
export function createAuthenticatedUser(
  session: SessionWithRelations,
): AuthenticatedUser {
  // Function unchanged
  const { user } = session;

  // Extract roles and permissions
  const roles = user.userRoles.map((ur) => ur.role.name);
  const permissions = Array.from(
    new Set(user.userRoles.flatMap((ur) => ur.role.permissions)),
  );

  return {
    id: user.id,
    username: user.username,
    email: user.email,
    isEmailVerified: user.isEmailVerified,
    isBanned: user.isBanned,
    createdAt: user.createdAt,
    updatedAt: user.updatedAt,
    displayName: user.displayName,
    avatarUrl: user.avatarUrl,
    roles,
    permissions,
  };
}

/**
 * Processes a request and creates an authenticated context if possible
 *
 * @param prisma - Prisma client instance
 * @param config - Authentication configuration
 * @param endpoints - Rate limiters by endpoint
 * @param headers - Request headers
 * @returns Response with authentication context
 */
export const processRequest = createOperation(
  "processRequest",
  ErrorCode.GENERAL_ERROR,
  "Failed to process request",
)(
  async (
    prisma: PrismaClient,
    config: AegisAuthConfig,
    endpoints: Endpoints,
    headers: Headers,
  ): Promise<
    AegisResponse<
      AegisContext & { cookies?: { sessionCookie: string; csrfCookie: string } }
    >
  > => {
    // Create base context
    const contextResult = createBaseContext(prisma, config, endpoints, headers);
    if (!contextResult.success) {
      return contextResult;
    }

    const ctx = contextResult.data;
    // Use sessionToken from the context instead of calling parseRequestAuth again
    const { sessionToken } = ctx.req;

    // If no session token, return unauthenticated context
    if (!sessionToken) {
      return success(ctx);
    }

    try {
      // Validate session
      const sessionResult = await validateSession(
        prisma,
        config,
        sessionToken,
        headers,
      );
      if (!sessionResult.success) {
        // Return unauthenticated context without exposing the reason
        config.logger?.debug("Session validation failed", {
          reason: sessionResult.error.code,
          message: sessionResult.error.message,
          ipAddress: ctx.req.ipAddress,
        });

        return success(ctx);
      }

      // Create authenticated context
      const { session, rotated, sessionCookie, csrfCookie } =
        sessionResult.data;
      const user = createAuthenticatedUser(session as SessionWithRelations);

      const authenticatedCtx = {
        ...ctx,
        auth: {
          isAuthenticated: true,
          user,
          session: session as SessionWithRelations,
        },
      };

      // Add cookies if session was rotated
      if (rotated && sessionCookie && csrfCookie) {
        return success({
          ...authenticatedCtx,
          cookies: {
            sessionCookie,
            csrfCookie,
          },
        });
      }

      return success(authenticatedCtx);
    } catch (error) {
      // On any error, return unauthenticated context
      config.logger?.error("Failed to process authenticated request", {
        error: error instanceof Error ? error.message : String(error),
        ipAddress: ctx.req.ipAddress,
      });

      return success(ctx);
    }
  },
);
