import { signSessionToken } from "../security";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaSession,
} from "../types";

export async function logoutUser(ctx: CoreContext): Promise<ActionResponse> {
  const { parsedRequest, prisma, config } = ctx;
  const { sessionToken } = parsedRequest || {};

  try {
    if (!sessionToken) {
      return {
        success: false,
        status: 401,
        message: "No session token provided",
        code: ErrorCodes.SESSION_NOT_FOUND,
      };
    }

    const tokenHash = await signSessionToken({ sessionToken, config });
    const session = (await prisma.session.findUnique({
      where: { tokenHash },
    })) as PrismaSession | null;

    if (!session) {
      return {
        success: false,
        status: 401,
        message: "Invalid session token",
        code: ErrorCodes.SESSION_INVALID,
      };
    }

    await prisma.session.update({
      where: { id: session.id },
      data: { isRevoked: true },
    });

    return {
      success: true,
      status: 200,
      message: "User logged out successfully",
    };
  } catch (error) {
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while logging out the user",
      code: ErrorCodes.INTERNAL_ERROR,
    };
  }
}
