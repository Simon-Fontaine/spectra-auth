import { generateCsrfToken, generateSessionToken } from "../security";
import {
  type ActionResponse,
  type ClientSession,
  type CoreContext,
  ErrorCodes,
} from "../types";
import { clientSafeSession, createTime } from "../utils";
import { createSessionSchema } from "../validations";

export async function createSession(
  context: CoreContext,
  input: {
    userId: string;
  },
): Promise<ActionResponse<{ session: ClientSession }>> {
  const { prisma, config, parsedRequest } = context;
  const { sessionToken, csrfToken, ...sessionInfo } = parsedRequest ?? {};

  try {
    // Validate input
    const validatedInput = createSessionSchema.safeParse(input);
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
      where: {
        userId: userId,
        isRevoked: false,
      },
    });

    if (
      config.session.maxSessionsPerUser > 0 &&
      activeSessions >= config.session.maxSessionsPerUser
    ) {
      config.logger.securityEvent("SESSION_LIMIT_REACHED", {
        userId: userId,
        maxSessionsPerUser: config.session.maxSessionsPerUser,
      });

      return {
        success: false,
        status: 400,
        message: "Session limit reached",
        code: ErrorCodes.SESSION_LIMIT_REACHED,
      };
    }

    const sessionTokens = await generateSessionToken({ config });
    const sessionExpiry = createTime(
      config.session.maxAgeSeconds,
      "s",
    ).getDate();
    const csrfTokens = await generateCsrfToken({ config });

    const session = await prisma.session.create({
      data: {
        csrfTokenHash: csrfTokens.csrfTokenHash,
        tokenHash: sessionTokens.sessionTokenHash,
        expiresAt: sessionExpiry,
        userId: userId,
        ...sessionInfo,
      },
    });

    config.logger.securityEvent("SESSION_CREATED", {
      sessionId: session.id,
      userId: userId,
    });

    const clientSession = clientSafeSession({
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
    config.logger.error("Error creating session", {
      error,
      userId: input.userId,
    });
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred.",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
