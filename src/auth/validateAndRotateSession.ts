import {
  type ActionResponse,
  type ClientSession,
  type CoreContext,
  ErrorCodes,
} from "../types";
import { createSession } from "./createSession";
import { validateSession } from "./validateSession";

export async function validateAndRotateSession(
  ctx: CoreContext,
): Promise<ActionResponse<{ session?: ClientSession }>> {
  const { prisma, config } = ctx;

  try {
    const isValidSession = await validateSession(ctx);
    if (!isValidSession.success || !isValidSession.data?.session) {
      return isValidSession;
    }

    const session = isValidSession.data.session;

    const now = new Date();
    const timeSinceLastRefresh = now.getTime() - session.updatedAt.getTime();
    const shouldRefresh =
      timeSinceLastRefresh >
      config.security.session.refreshIntervalSeconds * 1000;

    if (!shouldRefresh) {
      return isValidSession;
    }

    const newSessionRequest = await createSession(ctx, {
      userId: session.userId,
    });

    if (!newSessionRequest.success || !newSessionRequest.data?.session) {
      return newSessionRequest;
    }

    await prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true },
    });

    return newSessionRequest;
  } catch (error) {
    return {
      success: false,
      status: 500,
      message:
        "An unexpected error occurred while validating and rotating the session",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
