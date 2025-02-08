import type { PrismaClient } from "@prisma/client";
import type { SpectraAuthConfig } from "../config";
import { generateCsrfToken, generateSessionToken } from "../security";
import type { ActionResponse, ClientSession } from "../types";
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
  config: Required<SpectraAuthConfig>;
}): Promise<ActionResponse<{ session: ClientSession }>> {
  const sessionTokens = await generateSessionToken({ config });
  const sessionExpiry = createTime(config.session.maxAgeSeconds, "s").getDate();
  const csrfTokens = await generateCsrfToken({ config });

  const session = await prisma.session.create({
    data: {
      csrfTokenHash: csrfTokens.csrfTokenHash,
      tokenHash: sessionTokens.sessionTokenHash,
      tokenPrefix: sessionTokens.sessionPrefix,
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
