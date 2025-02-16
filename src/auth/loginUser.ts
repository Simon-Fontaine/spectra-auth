import { z } from "zod";
import { verifyPassword } from "../security";
import {
  type ActionResponse,
  type ClientSession,
  type ClientUser,
  type CoreContext,
  ErrorCodes,
  type PasswordPolicy,
  type PrismaUser,
} from "../types";
import { createTime, limitIpAddress, transformUser } from "../utils";
import {
  getEmailSchema,
  getPasswordSchema,
  getUsernameSchema,
} from "../validations";
import { createSession } from "./createSession";

const schema = (policy?: PasswordPolicy) =>
  z.object({
    usernameOrEmail: z.union([getEmailSchema(), getUsernameSchema()]),
    password: getPasswordSchema("Password", policy),
  });

export async function loginUser(
  ctx: CoreContext,
  options: { usernameOrEmail: string; password: string },
): Promise<ActionResponse<{ user?: ClientUser; session?: ClientSession }>> {
  const { parsedRequest, prisma, config, endpoints } = ctx;
  const { ipAddress } = parsedRequest ?? {};

  try {
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

    const { usernameOrEmail, password } = validatedInput.data;

    if (config.protection.rateLimit.endpoints.login.enabled && ipAddress) {
      const limiter = endpoints.login;
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

    const user = (await prisma.user.findFirst({
      where: {
        OR: [{ email: usernameOrEmail }, { username: usernameOrEmail }],
      },
    })) as PrismaUser | null;

    if (!user) {
      return {
        success: false,
        status: 401,
        message: "Invalid credentials",
        code: ErrorCodes.AUTH_INVALID_CREDENTIALS,
        data: null,
      };
    }

    if (user.isBanned) {
      return {
        success: false,
        status: 403,
        message: "Account is banned",
        code: ErrorCodes.ACCOUNT_DISABLED,
        data: null,
      };
    }

    const now = new Date();
    if (user.lockedUntil && user.lockedUntil > now) {
      const lockedUntil = createTime(user.lockedUntil.getTime(), "ms");

      return {
        success: false,
        status: 403,
        message: `Account locked. Try again ${lockedUntil.fromNow}.`,
        code: ErrorCodes.ACCOUNT_LOCKED,
        data: null,
      };
    }

    const passwordValid = await verifyPassword({
      hash: user.password,
      password: password,
      config,
    });

    if (!passwordValid) {
      const failedAttempts = user.failedLoginAttempts + 1;
      const maxAttempts = config.auth.login.maxFailedAttempts;
      const lockDuration = createTime(
        config.auth.login.lockoutDurationSeconds,
        "ms",
      );

      if (failedAttempts >= maxAttempts) {
        await prisma.user.update({
          where: { id: user.id },
          data: {
            failedLoginAttempts: 0,
            lockedUntil: lockDuration.getDate(),
          },
        });

        return {
          success: false,
          status: 403,
          message: `Account locked. Try again ${lockDuration.fromNow}.`,
          code: ErrorCodes.ACCOUNT_LOCKED,
          data: null,
        };
      }

      await prisma.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts: failedAttempts },
      });

      return {
        success: false,
        status: 401,
        message: "Invalid credentials",
        code: ErrorCodes.AUTH_INVALID_CREDENTIALS,
        data: null,
      };
    }

    if (
      !user.isEmailVerified &&
      config.auth.registration.requireEmailVerification
    ) {
      return {
        success: false,
        status: 403,
        message: "Email not verified",
        code: ErrorCodes.EMAIL_NOT_VERIFIED,
        data: null,
      };
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });

    const sessionRequest = await createSession(ctx, { userId: user.id });
    if (!sessionRequest.success || !sessionRequest.data?.session) {
      return sessionRequest;
    }

    return {
      success: true,
      status: 200,
      message: "Login successful",
      data: {
        user: transformUser({ user }),
        session: sessionRequest.data.session,
      },
    };
  } catch (error) {
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred while logging in the user",
      code: ErrorCodes.INTERNAL_ERROR,
      data: null,
    };
  }
}
