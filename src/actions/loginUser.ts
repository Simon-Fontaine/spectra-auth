import type { PrismaClient } from "@prisma/client";
import type { Ratelimit } from "@upstash/ratelimit";
import type { AegisAuthConfig } from "../config";
import { verifyPassword } from "../security";
import {
  type ActionResponse,
  type ClientSession,
  type ClientUser,
  ErrorCodes,
  type Limiters,
  type PrismaUser,
} from "../types";
import {
  type ParsedRequestData,
  clientSafeUser,
  createTime,
  limitIpAttempts,
} from "../utils";
import { loginSchema } from "../validations";
import { createSession } from "./createSession";

export async function loginUser(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
    limiters: Limiters;
    parsedRequest: ParsedRequestData;
  },
  input: {
    usernameOrEmail: string;
    password: string;
  },
): Promise<ActionResponse<{ user: ClientUser; session: ClientSession }>> {
  const { prisma, config, limiters, parsedRequest } = context;
  const { ipAddress } = parsedRequest ?? {};

  try {
    // Validate input using Zod schema.
    const credentials = loginSchema.safeParse(input);
    if (!credentials.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "login",
        ipAddress,
        ...input,
      });
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
      };
    }
    const { usernameOrEmail, password } = credentials.data;

    if (config.rateLimiting.login.enabled && ipAddress) {
      const limiter = limiters.login as Ratelimit;
      const limit = await limitIpAttempts({ ipAddress, limiter });
      if (!limit.success) {
        config.logger.securityEvent("RATE_LIMIT_EXCEEDED", {
          route: "login",
          ipAddress,
        });
        return {
          success: false,
          status: 429,
          message: "Too many attempts. Try again later.",
          code: ErrorCodes.RATE_LIMIT_EXCEEDED,
        };
      }
    }

    const user = (await prisma.user.findFirst({
      where: {
        OR: [{ email: usernameOrEmail }, { username: usernameOrEmail }],
      },
    })) as PrismaUser | null;

    if (!user) {
      config.logger.securityEvent("INVALID_CREDENTIALS", {
        route: "login",
        ipAddress,
        ...input,
      });
      return {
        success: false,
        status: 401,
        message: "Invalid credentials",
        code: ErrorCodes.INVALID_CREDENTIALS,
      };
    }

    if (user.isBanned) {
      config.logger.securityEvent("ACCOUNT_BANNED", {
        route: "login",
        ipAddress,
        userId: user.id,
      });
      return {
        success: false,
        status: 403,
        message: "Account is banned",
        code: ErrorCodes.ACCOUNT_BANNED,
      };
    }

    if (user.lockedUntil && user.lockedUntil > new Date()) {
      config.logger.securityEvent("ACCOUNT_LOCKED", {
        route: "login",
        ipAddress,
        userId: user.id,
      });
      const lockedUntil = createTime(user.lockedUntil.getTime(), "ms");
      return {
        success: false,
        status: 403,
        message: `Account locked. Try again ${lockedUntil.fromNow}.`,
        code: ErrorCodes.ACCOUNT_LOCKED,
      };
    }

    const passwordMatch = await verifyPassword({
      hash: user.password,
      password: password,
      config,
    });
    if (!passwordMatch) {
      config.logger.securityEvent("INVALID_CREDENTIALS", {
        route: "login",
        ipAddress,
        userId: user.id,
      });
      let failedLoginAttempts = user.failedLoginAttempts + 1;
      let lockedUntil: Date | null = null;
      if (failedLoginAttempts >= config.accountSecurity.maxFailedLogins) {
        lockedUntil = createTime(
          config.accountSecurity.lockoutDurationSeconds,
          "s",
        ).getDate();
        failedLoginAttempts = 0;
        config.logger.securityEvent("ACCOUNT_LOCKED", {
          route: "login",
          ipAddress,
          userId: user.id,
        });
      }
      await prisma.user.update({
        where: { id: user.id },
        data: { failedLoginAttempts, lockedUntil },
      });
      return {
        success: false,
        status: 401,
        message: "Invalid credentials",
        code: ErrorCodes.INVALID_CREDENTIALS,
      };
    }

    if (
      !user.isEmailVerified &&
      config.accountSecurity.requireEmailVerification
    ) {
      config.logger.securityEvent("EMAIL_NOT_VERIFIED", {
        route: "login",
        ipAddress,
        userId: user.id,
      });
      return {
        success: false,
        status: 403,
        message: "Email not verified",
        code: ErrorCodes.EMAIL_NOT_VERIFIED,
      };
    }

    await prisma.user.update({
      where: { id: user.id },
      data: { failedLoginAttempts: 0, lockedUntil: null },
    });

    const newSession = await createSession(context, {
      userId: user.id,
    });

    if (!newSession.success || !newSession.data?.session) {
      return {
        success: false,
        status: 500,
        message: "Failed to create session",
        code: ErrorCodes.INTERNAL_SERVER_ERROR,
      };
    }

    config.logger.securityEvent("LOGIN_SUCCESS", {
      route: "login",
      ipAddress,
      userId: user.id,
    });

    const clientUser = clientSafeUser({ user });

    return {
      success: true,
      status: 200,
      message: "Login successful",
      data: { user: clientUser, session: newSession.data.session },
    };
  } catch (err) {
    config.logger.error("Unexpected error in loginUser", { error: err });
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
