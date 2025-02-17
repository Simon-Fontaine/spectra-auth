import { z } from "zod";
import { sendVerificationEmail } from "../emails/sendVerificationEmail";
import { hashPassword } from "../security";
import {
  type ActionResponse,
  type ClientUser,
  type CoreContext,
  ErrorCodes,
  type PasswordPolicy,
  type PrismaUser,
} from "../types";
import { limitIpAddress, transformUser } from "../utils";
import {
  getEmailSchema,
  getPasswordSchema,
  getUsernameSchema,
} from "../validations";
import { createVerificationCore } from "./createVerificationCore";

const schema = (policy?: PasswordPolicy) =>
  z.object({
    username: getUsernameSchema(),
    email: getEmailSchema(),
    password: getPasswordSchema("Password", policy),
  });

export async function registerUserCore(
  ctx: CoreContext,
  options: { username: string; email: string; password: string },
): Promise<ActionResponse<{ user?: ClientUser }>> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { logger } = config;
  const { ipAddress } = parsedRequest ?? {};

  logger?.info("registerUser attempt", { ip: ipAddress, email: options.email });

  try {
    if (!config.auth.registration.enabled) {
      logger?.warn("registerUser disabled", { ip: ipAddress });
      return {
        success: false,
        status: 400,
        message: "User registration is disabled",
        code: ErrorCodes.REGISTRATION_DISABLED,
        data: null,
      };
    }

    const parsed = schema(config.auth.password.rules).safeParse(options);
    if (!parsed.success) {
      logger?.warn("registerUser invalid input", {
        errors: parsed.error.errors,
        ip: ipAddress,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }

    const { username, email, password } = parsed.data;

    if (config.protection.rateLimit.endpoints.register.enabled && ipAddress) {
      const limiter = endpoints.register;
      if (!limiter) {
        logger?.error("registerUser rateLimiter not initialized", {
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
        logger?.warn("registerUser rate limit exceeded", { ip: ipAddress });
        return {
          success: false,
          status: 429,
          message: "Too many requests. Try again later.",
          code: ErrorCodes.RATE_LIMIT_EXCEEDED,
          data: null,
        };
      }
    }

    const existingUser = (await prisma.user.findFirst({
      where: {
        OR: [{ email }, { username }],
      },
    })) as PrismaUser | null;

    if (existingUser) {
      logger?.warn("registerUser user exists", {
        username,
        email,
        ip: ipAddress,
      });
      return {
        success: false,
        status: 409,
        message: "User already exists",
        code: ErrorCodes.REGISTRATION_USER_EXISTS,
        data: null,
      };
    }

    const hashedPassword = await hashPassword({ password, config });
    const user = (await prisma.user.create({
      data: {
        username,
        email,
        password: hashedPassword,
        isEmailVerified: !config.auth.registration.requireEmailVerification,
      },
    })) as PrismaUser;

    logger?.info("registerUser success", { userId: user.id, ip: ipAddress });

    if (config.auth.registration.requireEmailVerification) {
      const verificationRequest = await createVerificationCore(ctx, {
        userId: user.id,
        type: "CONFIRM_EMAIL_AFTER_REGISTER",
      });

      if (
        !verificationRequest.success ||
        !verificationRequest.data?.verification
      ) {
        logger?.error("registerUser verification error", {
          userId: user.id,
          ip: ipAddress,
        });

        return {
          success: false,
          status: 500,
          message: "An unexpected error occurred while registering the user",
          code: ErrorCodes.INTERNAL_ERROR,
          data: null,
        };
      }

      const { token } = verificationRequest.data.verification;
      await sendVerificationEmail(ctx, {
        toEmail: user.email,
        token,
        type: "CONFIRM_EMAIL_AFTER_REGISTER",
        callbackUrl: `${config.core.baseUrl}/verify-email?token=`,
      });
    }

    return {
      success: true,
      status: 201,
      message: "User registered successfully",
      data: { user: transformUser({ user }) },
    };
  } catch (error) {
    logger?.error("registerUser error", {
      error: error instanceof Error ? error.message : String(error),
      ip: ipAddress,
    });

    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while registering the user",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
