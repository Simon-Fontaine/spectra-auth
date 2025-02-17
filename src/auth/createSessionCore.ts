import { z } from "zod";
import { generateCsrfToken, generateSessionToken } from "../security";
import {
  type ActionResponse,
  type ClientSession,
  type CoreContext,
  ErrorCodes,
  type PrismaSession,
} from "../types";
import { createTime, transformSession } from "../utils";

const schema = z.object({
  userId: z.string().uuid("Invalid user ID provided."),
});

export async function createSessionCore(
  ctx: CoreContext,
  options: { userId: string },
): Promise<ActionResponse<{ session?: ClientSession }>> {
  const { parsedRequest, prisma, config } = ctx;
  const { logger } = config;

  logger?.info("createSession called", {
    userId: options.userId,
    ip: parsedRequest?.ipAddress,
  });

  const {
    sessionToken: _sessionToken,
    csrfToken: _csrfToken,
    headers: _headers,
    ...sessionInfo
  } = parsedRequest ?? {};

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("createSession validation failed", {
        reason: "Invalid input",
        errors: parsed.error.errors,
      });

      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }

    const { userId } = parsed.data;
    const activeSessions = await prisma.session.count({
      where: { userId, isRevoked: false },
    });

    if (
      config.auth.session.maxSessionsPerUser > 0 &&
      activeSessions >= config.auth.session.maxSessionsPerUser
    ) {
      logger?.warn("createSession blocked", {
        userId,
        reason: "Max sessions per user exceeded",
      });

      return {
        success: false,
        status: 403,
        message: "Max sessions per user exceeded",
        code: ErrorCodes.SESSION_LIMIT_EXCEEDED,
        data: null,
      };
    }

    const sessionTokens = await generateSessionToken({ config });
    const expiresAt = createTime(
      config.security.session.cookie.maxAge,
      "s",
    ).getDate();
    const csrfTokens = await generateCsrfToken({ config });

    const session = (await prisma.session.create({
      data: {
        userId,
        tokenHash: sessionTokens.sessionTokenHash,
        csrfTokenHash: csrfTokens.csrfTokenHash,
        ...sessionInfo,
        expiresAt,
      },
    })) as PrismaSession;

    const clientSession = transformSession({
      session: session,
      sessionToken: sessionTokens.sessionToken,
      csrfToken: csrfTokens.csrfToken,
    });

    logger?.info("createSession success", {
      userId,
      sessionId: session.id,
      ip: parsedRequest?.ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: "Session created",
      data: { session: clientSession },
    };
  } catch (error) {
    logger?.error("createSession error", {
      error: error instanceof Error ? error.message : String(error),
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while creating the session",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
