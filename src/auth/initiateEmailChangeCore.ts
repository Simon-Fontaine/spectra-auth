import { z } from "zod";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaUser,
} from "../types";
import { limitIpAddress } from "../utils";
import { getEmailSchema } from "../validations";
import { createVerificationCore } from "./createVerificationCore";

const schema = z.object({
  userId: z.string().min(1),
  newEmail: getEmailSchema(),
});

export async function initiateEmailChangeCore(
  ctx: CoreContext,
  options: {
    userId: string;
    newEmail: string;
  },
): Promise<ActionResponse> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest ?? {};

  logger?.info("initiateEmailChangeCore called", {
    userId: options.userId,
    ip: ipAddress,
    newEmail: options.newEmail,
  });

  try {
    const validatedInput = schema.safeParse(options);
    if (!validatedInput.success) {
      logger?.warn("initiateEmailChangeCore invalid input", {
        errors: validatedInput.error.errors,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }
    const { userId, newEmail } = validatedInput.data;

    if (
      config.protection.rateLimit.endpoints.initiateEmailChange.enabled &&
      ipAddress
    ) {
      const limiter = endpoints.initiateEmailChange;
      if (!limiter) {
        logger?.error("initiateEmailChange rateLimiter not initialized", {
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
        logger?.warn("initiateEmailChange rate limit exceeded", {
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

    return {
      success: true,
      status: 200,
      message: "Email change initiated",
      data: null,
    };
  } catch (error) {
    logger?.error("initiateEmailChangeCore error", {
      error: error instanceof Error ? error.message : String(error),
      userId: options.userId,
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
