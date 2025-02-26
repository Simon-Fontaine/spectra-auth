import { ErrorCode } from "../../constants";
import { revokeSession } from "../../security/session";
import type { AegisContext, AegisResponse } from "../../types";
import { getClearCookies } from "../../utils/cookies";
import { createOperation } from "../../utils/error";
import { fail, success } from "../../utils/response";

/**
 * Logs out a user by revoking their session
 *
 * @param ctx - Authentication context
 * @returns Response with logout result
 */
export const logout = createOperation(
  "logout",
  ErrorCode.AUTH_NOT_AUTHENTICATED,
  "Failed to log out",
)(
  async (
    ctx: AegisContext,
  ): Promise<
    AegisResponse<{ cookies: { sessionCookie: string; csrfCookie: string } }>
  > => {
    const { config, auth } = ctx;

    // Check if user is authenticated
    if (!auth.isAuthenticated || !auth.session) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Not authenticated");
    }

    // Revoke the current session
    await revokeSession(ctx.prisma, auth.session.id);

    // Get cookies that clear the session
    const cookies = getClearCookies(config);

    ctx.config.logger?.info("User logged out successfully", {
      userId: auth.user?.id,
      sessionId: auth.session.id,
    });

    return success({ cookies });
  },
);

/**
 * Logs out a user from all sessions
 *
 * @param ctx - Authentication context
 * @returns Response with logout result
 */
export const logoutAll = createOperation(
  "logoutAll",
  ErrorCode.AUTH_NOT_AUTHENTICATED,
  "Failed to log out from all sessions",
)(
  async (
    ctx: AegisContext,
  ): Promise<
    AegisResponse<{
      cookies: { sessionCookie: string; csrfCookie: string };
      sessionsRevoked: number;
    }>
  > => {
    const { config, prisma, auth } = ctx;

    // Check if user is authenticated
    if (!auth.isAuthenticated || !auth.user || !auth.session) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Not authenticated");
    }

    // Revoke all user sessions
    const result = await prisma.session.updateMany({
      where: {
        userId: auth.user.id,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
      },
    });

    // Get cookies that clear the session
    const cookies = getClearCookies(config);

    ctx.config.logger?.info("User logged out from all sessions", {
      userId: auth.user.id,
      sessionsRevoked: result.count,
    });

    return success({
      cookies,
      sessionsRevoked: result.count,
    });
  },
);
