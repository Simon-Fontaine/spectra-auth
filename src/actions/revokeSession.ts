import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { signSessionToken } from "../security";
import type { ActionResponse, PrismaSession } from "../types";

export async function revokeSession(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
  },
  input: {
    sessionToken: string;
  },
): Promise<ActionResponse> {
  const { prisma, config } = context;
  const { sessionToken } = input;
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
