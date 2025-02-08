import type { PrismaClient } from "@prisma/client";
import type { SpectraAuthConfig } from "../config";
import { getSessionTokenPrefix } from "../security";
import type { ActionResponse, PrismaSession } from "../types";

export async function revokeSession({
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
  config: Required<SpectraAuthConfig>;
}): Promise<ActionResponse> {
  const { sessionToken } = options.input;
  const sessionPrefix = getSessionTokenPrefix({ token: sessionToken });

  const session = (await prisma.session.findUnique({
    where: { tokenPrefix: sessionPrefix },
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

  await prisma.session.update({
    where: { id: session.id },
    data: { isRevoked: true },
  });

  config.logger.securityEvent("SESSION_REVOKED", {
    sessionId: session.id,
  });

  return {
    success: true,
    status: 200,
    message: "Session revoked",
  };
}
