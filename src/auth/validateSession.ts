import { signSessionToken, verifyCsrfToken } from "../security";
import {
  type ActionResponse,
  type ClientSession,
  type CoreContext,
  ErrorCodes,
  type PrismaSession,
} from "../types";
import { transformSession } from "../utils";

export async function validateSession(
  ctx: CoreContext,
): Promise<ActionResponse<{ session?: ClientSession }>> {
  const { parsedRequest, prisma, config } = ctx;
  const { logger } = config;
  const { sessionToken, csrfToken, ipAddress } = parsedRequest || {};

  logger?.info("validateSession called", { ip: ipAddress });

  try {
    if (!sessionToken) {
      logger?.warn("validateSession no session token", { ip: ipAddress });
      return {
        success: false,
        status: 401,
        message: "No session token provided",
        code: ErrorCodes.SESSION_NOT_FOUND,
      };
    }

    const tokenHash = await signSessionToken({ sessionToken, config });
    const session = (await prisma.session.findUnique({
      where: { tokenHash },
    })) as PrismaSession | null;

    if (!session) {
      logger?.warn("validateSession invalid token", { ip: ipAddress });
      return {
        success: false,
        status: 401,
        message: "Invalid session token",
        code: ErrorCodes.SESSION_INVALID,
      };
    }

    if (session.isRevoked) {
      logger?.warn("validateSession revoked session", {
        sessionId: session.id,
        ip: ipAddress,
      });
      return {
        success: false,
        status: 401,
        message: "Revoked session token",
        code: ErrorCodes.SESSION_REVOKED,
      };
    }

    const now = new Date();
    const expiresAt = new Date(session.expiresAt);
    const isExpired = now > expiresAt;
    const isMaxLifetime =
      session.createdAt <
      new Date(
        now.getTime() - config.security.session.maxLifetimeSeconds * 1000,
      );

    if (isExpired || isMaxLifetime) {
      logger?.info("validateSession session expired", {
        sessionId: session.id,
        isExpired,
        isMaxLifetime,
      });
      await prisma.session.update({
        where: { id: session.id },
        data: { isRevoked: true },
      });

      return {
        success: false,
        status: 401,
        message: "Expired session token",
        code: ErrorCodes.SESSION_EXPIRED,
      };
    }

    if (csrfToken) {
      const isValidCsrf = await verifyCsrfToken({
        token: csrfToken,
        hash: session.csrfTokenHash,
        config: config,
      });

      if (!isValidCsrf) {
        logger?.warn("validateSession invalid csrf", {
          sessionId: session.id,
          ip: ipAddress,
        });
        return {
          success: false,
          status: 401,
          message: "Invalid CSRF token",
          code: ErrorCodes.SECURITY_CSRF_INVALID,
        };
      }
    }

    logger?.info("validateSession success", {
      sessionId: session.id,
      ip: ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: "Session token is valid",
      data: { session: transformSession({ session, sessionToken, csrfToken }) },
    };
  } catch (error) {
    logger?.error("validateSession error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while validating the session",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
