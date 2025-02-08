import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { splitSessionToken, verifySessionToken } from "../security";
import {
  type ActionResponse,
  type ClientSession,
  ErrorCodes,
  type PrismaSession,
} from "../types";
import { createSession } from "./createSession";
import { revokeSession } from "./revokeSession";

export async function validateSession({
  options,
  prisma,
  config,
}: {
  options: {
    input: {
      sessionToken: string;
    };
  };
  prisma: PrismaClient;
  config: Required<AegisAuthConfig>;
}): Promise<ActionResponse<{ session?: ClientSession; rolled: boolean }>> {
  const { sessionToken } = options.input;
  const sessionTokens = await splitSessionToken({
    token: sessionToken,
    config,
  });

  const session = (await prisma.session.findUnique({
    where: { tokenPrefix: sessionTokens.tokenPrefix },
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
    token: session.tokenHash,
    hash: sessionTokens.tokenHash,
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

  let rolledSession: ClientSession | null = null;
  const { rollingIntervalSeconds } = config.session;

  const now = new Date();
  if (
    rollingIntervalSeconds > 0 &&
    now.getTime() - session.updatedAt.getTime() > rollingIntervalSeconds * 1000
  ) {
    const newSession = await createSession({
      options: {
        userId: session.userId,
        ipAddress: session.ipAddress || undefined,
        location: session.location || undefined,
        country: session.country || undefined,
        device: session.device || undefined,
        browser: session.browser || undefined,
        os: session.os || undefined,
        userAgent: session.userAgent || undefined,
      },
      prisma,
      config,
    });

    if (!newSession.success || !newSession.data?.session) {
      return {
        success: false,
        status: 500,
        message: "Failed to create new session",
        code: ErrorCodes.FAILED_TO_ROLL_SESSION,
      };
    }

    rolledSession = newSession.data.session;
    await revokeSession({
      options: {
        input: {
          sessionToken,
        },
      },
      prisma,
      config,
    });
  }

  if (rolledSession) {
    config.logger.securityEvent("SESSION_ROLLED", {
      sessionId: session.id,
    });
    return {
      success: true,
      status: 200,
      message: "Session validated and rolled",
      data: { session: rolledSession, rolled: true },
    };
  }

  return {
    success: true,
    status: 200,
    message: "Session validated",
    data: { rolled: false },
  };
}
