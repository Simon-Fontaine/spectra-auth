import { z } from "zod";
import { signSessionToken } from "../security";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaSession,
  type PrismaUser,
} from "../types";
import { limitIpAddress } from "../utils";
import { getEmailSchema } from "../validations";
import { createVerificationCore } from "./createVerificationCore";

const schema = z.object({
  newEmail: getEmailSchema(),
});

export async function initiateEmailChangeCore(
  ctx: CoreContext,
  options: {
    newEmail: string;
  },
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress, sessionToken } = parsedRequest ?? {};

  logger?.info("initiateEmailChangeCore called", {
    ip: ipAddress,
    newEmail: options.newEmail,
  });

  try {
    const parsed = schema.safeParse(options);
    if (!parsed.success) {
      logger?.warn("initiateEmailChangeCore invalid input", {
        errors: parsed.error.errors,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }
    const { newEmail } = parsed.data;

    if (
      config.protection.rateLimit.endpoints.initiateEmailChange.enabled &&
      ipAddress
    ) {
      const limiter = endpoints.initiateEmailChange;
      if (!limiter) {
        logger?.error("initiateEmailChangeCore rateLimiter not initialized", {
          ip: ipAddress,
        });
        return {
          success: false,
          status: 500,
          message: "Rate limiter not initialized",
          code: ErrorCodes.INTERNAL_ERROR,
          data: null,
        };
      }

      const limit = await limitIpAddress(ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("initiateEmailChangeCore rate limit exceeded", {
          ip: ipAddress,
        });
        return {
          success: false,
          status: 429,
          message: "Too many requests. Try again later.",
          code: ErrorCodes.RATE_LIMIT_EXCEEDED,
          data: null,
        };
      }
    }

    if (!sessionToken) {
      logger?.warn("initiateEmailChangeCore no session token", {
        ip: ipAddress,
      });
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

    if (!session || session.isRevoked) {
      logger?.warn("initiateEmailChangeCore invalid or revoked session", {
        ip: ipAddress,
      });
      return {
        success: false,
        status: 401,
        message: "Invalid or revoked session token",
        code: ErrorCodes.SESSION_INVALID,
      };
    }

    const userId = session.userId;

    const user = (await prisma.user.findUnique({
      where: { id: userId },
    })) as PrismaUser | null;

    if (!user) {
      logger?.warn("initiateEmailChangeCore user not found", {
        userId,
        newEmail,
      });
      return {
        success: false,
        status: 404,
        message: "User not found",
        code: ErrorCodes.ACCOUNT_NOT_FOUND,
        data: null,
      };
    }

    if (user.email.toLowerCase() === newEmail.toLowerCase()) {
      logger?.warn("initiateEmailChangeCore new email same as current", {
        userId,
        newEmail,
      });
      return {
        success: false,
        status: 400,
        message: "New email cannot be the same as current email",
        code: ErrorCodes.EMAIL_INVALID,
        data: null,
      };
    }

    const emailInUse = await prisma.user.findUnique({
      where: { email: newEmail },
    });

    if (emailInUse) {
      logger?.warn("initiateEmailChangeCore new email in use", {
        userId,
        newEmail,
      });
      return {
        success: false,
        status: 409,
        message: "Email already in use",
        code: ErrorCodes.REGISTRATION_EMAIL_EXISTS,
        data: null,
      };
    }

    await prisma.user.update({
      where: { id: userId },
      data: { pendingEmail: newEmail },
    });

    const verificationRequest = await createVerificationCore(ctx, {
      userId,
      type: "INITIATE_EMAIL_CHANGE",
    });

    if (
      !verificationRequest.success ||
      !verificationRequest.data?.verification
    ) {
      logger?.error("initiateEmailChangeCore createVerification error", {
        userId,
        newEmail,
      });
      return {
        success: false,
        status: 500,
        message:
          "An unexpected error occurred while initiating the email change",
        code: ErrorCodes.INTERNAL_ERROR,
        data: null,
      };
    }

    const { token } = verificationRequest.data.verification;
    // TODO: Send email with token
    console.log("Email change token:", token);

    logger?.info("initiateEmailChangeCore success", {
      userId,
      ip: ipAddress,
    });

    return {
      success: true,
      status: 200,
      message: "Email change initiated. Please confirm via verification token.",
      data: null,
    };
  } catch (error) {
    logger?.error("initiateEmailChangeCore error", {
      error: error instanceof Error ? error.message : String(error),
      newEmail: options.newEmail,
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while initiating email change",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
