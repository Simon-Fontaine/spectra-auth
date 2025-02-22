import type { AegisContext, AegisResponse } from "../types";
import { fail, success } from "../utils";

export async function logoutUserCore(
  ctx: AegisContext,
): Promise<AegisResponse<boolean>> {
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

    await prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true },
    });

    logger?.debug("Session revoked", { ip: req.ipAddress });

    return success(true);
  } catch (error) {
    logger?.error("Failed to logout user", { error, ip: req.ipAddress });
    return fail("LOGOUT_ERROR", "Failed to logout user.");
  }
}
