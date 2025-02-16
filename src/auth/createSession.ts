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
  userId: z.string().min(1),
});

export async function createSession(
  ctx: CoreContext,
  options: { userId: string },
): Promise<ActionResponse<{ session?: ClientSession }>> {
  const { parsedRequest, prisma, config } = ctx;
  const {
    sessionToken: _sessionToken,
    csrfToken: _csrfToken,
    headers: _headers,
    ...sessionInfo
  } = parsedRequest ?? {};

  try {
    const validatedInput = schema.safeParse(options);
    if (!validatedInput.success) {
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }

    const { userId } = validatedInput.data;
    const activeSessions = await prisma.session.count({
      where: { userId, isRevoked: false },
    });

    if (
      config.auth.session.maxSessionsPerUser > 0 &&
      activeSessions >= config.auth.session.maxSessionsPerUser
    ) {
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

    return {
      success: true,
      status: 200,
      message: "Session created",
      data: { session: clientSession },
    };
  } catch (error) {
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while creating the session",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
