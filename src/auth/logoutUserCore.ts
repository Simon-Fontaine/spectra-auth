import type { AegisContext, AegisResponse } from "../types";
import { fail, getClearSessionCookies, revokeSession, success } from "../utils";

export async function logoutUserCore(
  ctx: AegisContext,
): Promise<AegisResponse<{ cleared: boolean; cookies: string[] }>> {
  const { config, prisma, req, auth } = ctx;
  const { logger } = config;

  logger?.debug("logoutUser called", { ip: req.ipAddress });

  try {
    if (!auth.isAuthenticated) {
      return fail("NOT_LOGGED_IN_ERROR", "User is not logged in.");
    }

    const session = auth.session;
    if (!session) {
      return fail("NO_SESSION_ERROR", "No session found.");
    }

    await revokeSession(prisma, session.id);

    logger?.debug("Session revoked", { ip: req.ipAddress });

    const { sessionCookie, csrfCookie } = getClearSessionCookies(config);

    return success({ cleared: true, cookies: [sessionCookie, csrfCookie] });
  } catch (error) {
    logger?.error("Failed to logout user", { error, ip: req.ipAddress });
    return fail("LOGOUT_ERROR", "Failed to logout user.");
  }
}
