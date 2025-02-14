import type { PrismaClient } from "@prisma/client";
import { validateAndRotateSession } from "../actions";
import type { AegisAuthConfig } from "../config";
import { createCsrfCookie, createSessionCookie } from "../cookies";
import type { AegisAuth } from "../index";
import { verifyCsrfToken } from "../security";
import type { AuthHeaders } from "../types";
import { userHasPermission } from "../utils";

/** Context available to user’s handler. */
export interface AuthContext {
  userId: string;
  roles?: string[];
  req: Request;
  prisma: PrismaClient;
  config: AegisAuthConfig;
}

interface WithAuthOptions {
  /** If provided, user must have these permission(s) or we return 403. */
  permission?: string | string[];
  /** If true, perform CSRF checks for non-GET requests. */
  csrf?: boolean;
  /**
   * If you want to always set/refresh the session cookie on every request,
   * set this to true. Otherwise, we'll only set it if the session was rotated.
   */
  alwaysSetCookie?: boolean;
}

export function withAuth<T = unknown>(
  authInstance: AegisAuth,
  handler: (ctx: AuthContext) => Promise<T> | T,
  options?: WithAuthOptions,
) {
  return async (req: Request): Promise<Response> => {
    try {
      const baseContext = authInstance.createContextWithRequest({
        headers: req.headers as AuthHeaders,
      });

      if (!baseContext.parsedRequest.sessionToken) {
        return jsonResponse({ message: "No session token provided" }, 401);
      }

      const sessionResult = await validateAndRotateSession(baseContext, {
        sessionToken: baseContext.parsedRequest.sessionToken,
      });

      if (!sessionResult.success || !sessionResult.data?.session) {
        return jsonResponse(
          { message: sessionResult.message },
          sessionResult.status,
        );
      }

      const session = sessionResult.data.session;
      const userId = session.userId;

      const headers = new Headers({ "Content-Type": "application/json" });

      if (sessionResult.data.rolled || options?.alwaysSetCookie) {
        const sessionCookie = createSessionCookie({
          sessionToken: session.sessionToken,
          config: baseContext.config,
        });
        headers.append("Set-Cookie", sessionCookie);

        if (baseContext.config.csrf.enabled) {
          const csrfCookie = createCsrfCookie({
            csrfToken: session.csrfToken,
            config: baseContext.config,
          });
          headers.append("Set-Cookie", csrfCookie);
        }
      }

      const method = req.method.toUpperCase();
      if (
        (options?.csrf ?? false) &&
        !["GET", "HEAD", "OPTIONS"].includes(method)
      ) {
        const csrfTokenFromRequest = baseContext.parsedRequest.csrfToken;
        if (!csrfTokenFromRequest) {
          return jsonResponse({ message: "CSRF token missing" }, 403, headers);
        }

        const isValidCsrf = await verifyCsrfToken({
          token: csrfTokenFromRequest,
          hash: session.csrfToken,
          config: baseContext.config,
        });
        if (!isValidCsrf) {
          return jsonResponse({ message: "Invalid CSRF token" }, 403, headers);
        }
      }

      if (options?.permission) {
        const requiredPerms = Array.isArray(options.permission)
          ? options.permission
          : [options.permission];

        for (const perm of requiredPerms) {
          const canDo = await userHasPermission(userId, perm);
          if (!canDo) {
            return jsonResponse(
              { message: `Forbidden: missing permission ${perm}` },
              403,
              headers,
            );
          }
        }
      }

      const ctx: AuthContext = {
        userId,
        req,
        prisma: baseContext.prisma,
        config: baseContext.config,
      };

      const result = await handler(ctx);

      if (result !== undefined) {
        return jsonResponse(result, 200, headers);
      }
      return new Response(null, { status: 204, headers });
    } catch (err) {
      console.error("Unexpected error in withAuth:", err);
      return jsonResponse({ message: "Internal server error" }, 500);
    }
  };
}

function jsonResponse(
  data: unknown,
  status = 200,
  headers = new Headers({ "Content-Type": "application/json" }),
): Response {
  return new Response(JSON.stringify(data), { status, headers });
}
