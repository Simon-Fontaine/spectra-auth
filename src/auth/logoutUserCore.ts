import type { AegisContext, AegisResponse } from "../types";
import { fail, getClearSessionCookies, revokeSession, success } from "../utils";

export async function logoutUserCore(
  ctx: AegisContext,
): Promise<AegisResponse<{ cleared: boolean; cookies: string[] }>> {
  const { config, prisma, req, auth } = ctx;
  const { logger } = config;

  logger?.debug("logoutUserCore - invoked", { ipAddress: req.ipAddress });

  try {
    if (!auth.isAuthenticated) {
      logger?.warn("logoutUserCore - user is not authenticated", {
        ipAddress: req.ipAddress,
      });
      return fail("LOGOUT_NOT_AUTHENTICATED", "User is not authenticated.");
    }

    const session = auth.session;
    if (!session) {
      logger?.warn("logoutUserCore - no active session found", {
        userId: auth.user?.id,
        ipAddress: req.ipAddress,
      });
      return fail("LOGOUT_NO_SESSION", "No active session found to log out.");
    }

    await revokeSession(prisma, session.id);

    const { sessionCookie, csrfCookie } = getClearSessionCookies(config);

    logger?.info("logoutUserCore - user logged out successfully", {
      userId: auth.user?.id ?? session.userId,
      ipAddress: req.ipAddress,
    });

    return success({
      cleared: true,
      cookies: [sessionCookie, csrfCookie],
    });
  } catch (error) {
    logger?.error("logoutUserCore failed unexpectedly", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail("LOGOUT_ERROR", "Failed to log out user. Please try again.");
  }
}
