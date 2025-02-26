import { ErrorCode } from "../../constants";
import { getClearAuthCookies } from "../../http/cookies";
import { revokeSession } from "../../security/session";
import type { AegisContext, AegisResponse } from "../../types";
import { createOperation } from "../../utils/error";
import { fail, success } from "../../utils/response";

/**
 * Logs out the current session
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

    if (!auth.isAuthenticated || !auth.session) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Not authenticated");
    }

    await revokeSession(ctx.prisma, auth.session.id);
    const cookies = getClearAuthCookies(config);

    ctx.config.logger?.info("User logged out successfully", {
      userId: auth.user?.id,
      sessionId: auth.session.id,
    });

    return success({ cookies });
  },
);

/**
 * Logs out all sessions of the current user
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

    if (!auth.isAuthenticated || !auth.user || !auth.session) {
      return fail(ErrorCode.AUTH_NOT_AUTHENTICATED, "Not authenticated");
    }

    const result = await prisma.session.updateMany({
      where: {
        userId: auth.user.id,
        isRevoked: false,
      },
      data: {
        isRevoked: true,
      },
    });

    const cookies = getClearAuthCookies(config);

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
