import {
  type ActionResponse,
  type ClientSession,
  type CoreContext,
  ErrorCodes,
} from "../types";
import { createSessionCore } from "./createSessionCore";
import { validateSessionCore } from "./validateSessionCore";

export async function validateAndRotateSessionCore(
  ctx: CoreContext,
): Promise<ActionResponse<{ session?: ClientSession }>> {
  const { prisma, config } = ctx;
  const { logger } = config;

  logger?.info("validateAndRotateSession called", {});

  try {
    const isValidSession = await validateSessionCore(ctx);
    if (!isValidSession.success || !isValidSession.data?.session) {
      logger?.warn("validateAndRotateSession session invalid", {
        reason: isValidSession.message,
      });
      return isValidSession;
    }

    const session = isValidSession.data.session;
    const now = new Date();
    const timeSinceLastRefresh = now.getTime() - session.updatedAt.getTime();
    const shouldRefresh =
      timeSinceLastRefresh >
      config.security.session.refreshIntervalSeconds * 1000;

    if (!shouldRefresh) {
      logger?.info("validateAndRotateSession no rotation needed", {
        sessionId: session.id,
      });
      return isValidSession;
    }

    // create new session
    const newSessionRequest = await createSessionCore(ctx, {
      userId: session.userId,
    });

    if (!newSessionRequest.success || !newSessionRequest.data?.session) {
      logger?.warn("validateAndRotateSession new session creation failed", {
        userId: session.userId,
        reason: newSessionRequest.message,
      });
      return newSessionRequest;
    }

    await prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true },
    });

    logger?.info("validateAndRotateSession session rotated", {
      oldSessionId: session.id,
      newSessionId: newSessionRequest.data.session.id,
    });

    return newSessionRequest;
  } catch (error) {
    logger?.error("validateAndRotateSession error", {
      error: error instanceof Error ? error.message : String(error),
    });

    return {
      success: false,
      status: 500,
      message:
        "An unexpected error occurred while validating and rotating the session",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
