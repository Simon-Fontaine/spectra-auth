import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { signSessionToken, verifySessionToken } from "../security";
import {
  type ActionResponse,
  type ClientSession,
  ErrorCodes,
  type PrismaSession,
} from "../types";
import type { ParsedRequestData } from "../utils";
import { validateAndRotateSessionSchema } from "../validations";
import { createSession } from "./createSession";
import { revokeSession } from "./revokeSession";

export async function validateAndRotateSession(
  context: {
    prisma: PrismaClient;
    config: AegisAuthConfig;
    parsedRequest: ParsedRequestData;
  },
  input: {
    sessionToken: string;
  },
): Promise<ActionResponse<{ session?: ClientSession; rolled: boolean }>> {
  const { prisma, config } = context;

  try {
    const validatedInput = validateAndRotateSessionSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "validateAndRotateSession",
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { sessionToken } = validatedInput.data;

    const tokenHash = await signSessionToken({ sessionToken, config });

    const session = (await prisma.session.findUnique({
      where: { tokenHash },
    })) as PrismaSession | null;

    if (!session) {
      config.logger.securityEvent("SESSION_NOT_FOUND", {
        sessionToken,
      });

      return {
        success: false,
        status: 404,
        message: "Session not found",
      };
    }

    if (session.isRevoked) {
      config.logger.securityEvent("SESSION_REVOKED", {
        sessionId: session.id,
      });

      return {
        success: false,
        status: 401,
        message: "Session revoked",
      };
    }

    const isValidToken = await verifySessionToken({
      sessionToken,
      sessionTokenHash: session.tokenHash,
      config,
    });

    if (!isValidToken) {
      config.logger.securityEvent("SESSION_INVALID", {
        sessionId: session.id,
      });

      return {
        success: false,
        status: 401,
        message: "Session invalid",
      };
    }

    const now = new Date();
    const timeSinceLastUpdate = now.getTime() - session.updatedAt.getTime();
    const shouldRotate =
      config.session.rollingIntervalSeconds > 0 &&
      timeSinceLastUpdate > config.session.rollingIntervalSeconds * 1000;

    if (shouldRotate) {
      const newSession = await createSession(context, {
        userId: session.userId,
      });

      if (!newSession.success || !newSession.data?.session) {
        return {
          success: false,
          status: 500,
          message: "Failed to create new session",
          code: ErrorCodes.FAILED_TO_ROLL_SESSION,
        };
      }
      await revokeSession(context, {
        sessionToken,
      });

      config.logger.securityEvent("SESSION_ROTATED", {
        oldSessionId: session.id,
      });

      return {
        success: true,
        status: 200,
        message: "Session rotated",
        data: { session: newSession.data.session, rolled: true },
      };
    }

    return {
      success: true,
      status: 200,
      message: "Session validated",
      data: { rolled: false },
    };
  } catch (error) {
    config.logger.error("Error validating/rotating session", {
      error,
      sessionToken: input.sessionToken,
    });
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred.",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
