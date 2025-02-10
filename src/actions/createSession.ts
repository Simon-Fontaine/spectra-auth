import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { generateCsrfToken, generateSessionToken } from "../security";
import { type ActionResponse, type ClientSession, ErrorCodes } from "../types";
import { clientSafeSession, createTime } from "../utils";

export async function createSession({
  options,
  prisma,
  config,
}: {
  options: {
    userId: string;
    ipAddress?: string;
    location?: string;
    country?: string;
    device?: string;
    browser?: string;
    os?: string;
    userAgent?: string;
  };
  prisma: PrismaClient;
  config: Required<AegisAuthConfig>;
}): Promise<ActionResponse<{ session: ClientSession }>> {
  const activeSessions = await prisma.session.count({
    where: {
      userId: options.userId,
      isRevoked: false,
    },
  });

  if (
    config.session.maxSessionsPerUser > 0 &&
    activeSessions >= config.session.maxSessionsPerUser
  ) {
    config.logger.securityEvent("SESSION_LIMIT_REACHED", {
      userId: options.userId,
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
  const sessionExpiry = createTime(config.session.maxAgeSeconds, "s").getDate();
  const csrfTokens = await generateCsrfToken({ config });

  const session = await prisma.session.create({
    data: {
      csrfTokenHash: csrfTokens.csrfTokenHash,
      tokenHash: sessionTokens.sessionTokenHash,
      expiresAt: sessionExpiry,
      ...options,
    },
  });

  config.logger.securityEvent("SESSION_CREATED", {
    sessionId: session.id,
    ...options,
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
}
