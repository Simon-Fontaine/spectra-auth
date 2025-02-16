import { z } from "zod";
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

const schema = (policy?: PasswordPolicy) =>
  z.object({
    username: getUsernameSchema(),
    email: getEmailSchema(),
    password: getPasswordSchema("Password", policy),
  });

export async function registerUser(
  ctx: CoreContext,
  options: { username: string; email: string; password: string },
): Promise<ActionResponse<{ user?: ClientUser }>> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { ipAddress } = parsedRequest ?? {};

  try {
    if (!config.auth.registration.enabled) {
      return {
        success: false,
        status: 400,
        message: "User registration is disabled",
        code: ErrorCodes.REGISTRATION_DISABLED,
        data: null,
      };
    }

    const validatedInput = schema(config.auth.password.rules).safeParse(
      options,
    );
    if (!validatedInput.success) {
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }

    const { username, email, password } = validatedInput.data;

    if (config.protection.rateLimit.endpoints.register.enabled && ipAddress) {
      const limiter = endpoints.register;
      if (!limiter) {
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

    if (config.auth.registration.requireEmailVerification) {
      // Send verification email
    }

    return {
      success: true,
      status: 201,
      message: "User registered successfully",
      data: { user: transformUser({ user }) },
    };
  } catch (error) {
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while registering the user",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
