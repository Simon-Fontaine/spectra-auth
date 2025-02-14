import { signSessionToken } from "../security";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaSession,
} from "../types";
import { revokeSessionSchema } from "../validations";

export async function revokeSession(
  context: CoreContext,
  input: {
    sessionToken: string;
  },
): Promise<ActionResponse> {
  const { prisma, config } = context;

  try {
    const validatedInput = revokeSessionSchema.safeParse(input);
    if (!validatedInput.success) {
      config.logger.securityEvent("INVALID_INPUT", { route: "revokeSession" });
      return {
        success: false,
        status: 400,
        message: "Invalid input",
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
  } catch (error) {
    config.logger.error("Error revoking session", {
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
