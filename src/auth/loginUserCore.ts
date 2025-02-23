import { z } from "zod";
import { verifyPassword } from "../security";
import type { AegisContext, AegisResponse, PasswordConfig } from "../types";
import {
  type TimeObject,
  createSession,
  createTime,
  fail,
  getGeolocation,
  limitIpAddress,
  success,
} from "../utils";
import {
  getEmailSchema,
  getPasswordSchema,
  getUsernameSchema,
} from "../validations";

interface LoginRequest {
  usernameOrEmail: string;
  password: string;
}

interface LoginResponse {
  userId: string;
  cookies: string[];
}

const schema = (policy: PasswordConfig["rules"]) =>
  z.object({
    usernameOrEmail: z.union([getEmailSchema(), getUsernameSchema()]),
    password: getPasswordSchema("Password", policy),
  });

export async function loginUserCore(
  ctx: AegisContext,
  options: LoginRequest,
): Promise<AegisResponse<LoginResponse>> {
  const { config, prisma, req, endpoints } = ctx;
  const { logger } = config;

  logger?.debug("loginUserCore - invoked", {
    usernameOrEmail: options.usernameOrEmail,
    ipAddress: req.ipAddress,
  });

  try {
    const parsed = schema(config.password.rules).safeParse(options);
    if (!parsed.success) {
      logger?.debug("loginUserCore - validation error", {
        error: parsed.error.issues,
        ipAddress: req.ipAddress,
      });
      return fail("LOGIN_INVALID_REQUEST", "Invalid username or password.");
    }
    const { usernameOrEmail, password } = parsed.data;

    if (config.rateLimit.endpoints.login?.enabled && req.ipAddress) {
      const limiter = endpoints.login;
      if (!limiter) {
        logger?.error("loginUserCore - rate-limit endpoint missing", {
          ipAddress: req.ipAddress,
        });
        return fail("LOGIN_RATE_LIMIT_ERROR", "Server misconfiguration.");
      }
      const limit = await limitIpAddress(req.ipAddress, limiter);
      if (!limit.success) {
        logger?.warn("loginUserCore - rate limit exceeded", {
          ipAddress: req.ipAddress,
        });
        return fail(
          "LOGIN_RATE_LIMIT_EXCEEDED",
          "Too many requests. Please try again later.",
        );
      }
    }

    const user = await prisma.user.findFirst({
      where: {
        OR: [{ email: usernameOrEmail }, { username: usernameOrEmail }],
      },
      include: {
        userRoles: { include: { role: true } },
        sessions: true,
        passwordHistory: true,
      },
    });

    if (!user) {
      logger?.warn("loginUserCore - user not found", {
        usernameOrEmail,
        ipAddress: req.ipAddress,
      });
      return fail(
        "LOGIN_INVALID_CREDENTIALS",
        "Username or password is incorrect.",
      );
    }

    if (user.isBanned) {
      logger?.warn("loginUserCore - Banned user attempted login", {
        userId: user.id,
      });
      return fail("LOGIN_BANNED_USER", "This account is currently banned.");
    }

    const now = new Date();
    if (user.lockedUntil && user.lockedUntil > now) {
      const lockedUntilTime = createTime(user.lockedUntil.getTime(), "ms");
      logger?.warn("loginUserCore - account locked", {
        userId: user.id,
        lockedUntil: user.lockedUntil.toISOString(),
      });
      return fail(
        "LOGIN_USER_LOCKED_OUT",
        `Account is locked. Try again ${lockedUntilTime.fromNow()}.`,
      );
    }

    const pwCheck = await verifyPassword({
      hash: user.passwordHash,
      password,
      config,
    });

    if (!pwCheck.success || !pwCheck.data) {
      const updatedAttempts = user.failedLoginAttempts + 1;
      logger?.warn("loginUserCore - password mismatch", {
        userId: user.id,
        attempts: updatedAttempts,
      });

      let newLockedUntil: TimeObject | null = null;
      let lockUser = false;

      if (updatedAttempts >= config.login.maxFailedAttempts) {
        lockUser = true;
        newLockedUntil = createTime(config.login.lockoutDurationSeconds, "s");
      }

      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: updatedAttempts,
          lockedUntil: lockUser ? newLockedUntil?.getDate() : null,
        },
      });

      if (lockUser) {
        logger?.warn("loginUserCore - user locked out", {
          userId: user.id,
          attempts: updatedAttempts,
        });
        return fail(
          "LOGIN_USER_LOCKED_OUT",
          `Account is locked. Try again ${newLockedUntil?.fromNow()}.`,
        );
      }

      return fail(
        "LOGIN_INVALID_CREDENTIALS",
        "Username or password is incorrect.",
      );
    }

    if (user.failedLoginAttempts > 0 || user.lockedUntil) {
      await prisma.user.update({
        where: { id: user.id },
        data: {
          failedLoginAttempts: 0,
          lockedUntil: null,
        },
      });
    }

    if (!user.isEmailVerified && config.account.requireEmailVerification) {
      logger?.warn("loginUserCore - email not verified", { userId: user.id });
      return fail(
        "LOGIN_EMAIL_NOT_VERIFIED",
        "Please verify your email address before logging in.",
      );
    }

    const maxSessions = config.account.maxSimultaneousSessions;
    if (maxSessions > 0 && user.sessions.length >= maxSessions) {
      const oldestSession = user.sessions.reduce((oldest, current) => {
        return current.createdAt < oldest.createdAt ? current : oldest;
      }, user.sessions[0]);

      await prisma.session.update({
        where: { id: oldestSession.id },
        data: { isRevoked: true },
      });

      logger?.debug("loginUserCore - max sessions enforced", {
        userId: user.id,
        oldestSessionId: oldestSession.id,
      });
    }

    const geoResp = await getGeolocation(config, req.ipAddress, req.userAgent);
    if (!geoResp.success || !geoResp.data) {
      logger?.warn("loginUserCore - geolocation failed", {
        userId: user.id,
        error: geoResp.error?.message,
      });
      return fail(
        "LOGIN_GEO_LOOKUP_ERROR",
        "Location data unavailable. Please try again later.",
      );
    }

    const { sessionCookie, csrfCookie } = await createSession(
      prisma,
      config,
      user.id,
      req.ipAddress,
      geoResp.data.locationData,
      geoResp.data.deviceData,
    );

    logger?.info("loginUserCore - User login successful", { userId: user.id });

    return success({
      userId: user.id,
      cookies: [sessionCookie, csrfCookie],
    });
  } catch (error) {
    logger?.error("loginUserCore - failed unexpectedly", {
      error: error instanceof Error ? error.message : String(error),
      ipAddress: req.ipAddress,
    });
    return fail("LOGIN_ERROR", "An unexpected error occurred during login.");
  }
}
