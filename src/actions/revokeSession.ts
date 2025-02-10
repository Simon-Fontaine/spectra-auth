import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { signSessionToken } from "../security";
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
  config: Required<AegisAuthConfig>;
}): Promise<ActionResponse> {
  const { sessionToken } = options.input;
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
