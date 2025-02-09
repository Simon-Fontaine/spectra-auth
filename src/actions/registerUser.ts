import { type PrismaClient, VerificationType } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import { sendVerificationEmail } from "../emails";
import { hashPassword } from "../security";
import {
  type ActionResponse,
  type ClientUser,
  ErrorCodes,
  type PrismaUser,
} from "../types";
import { clientSafeUser, createRouteLimiter, limitIpAttempts } from "../utils";
import { registerSchema } from "../validations/registerSchema";
import { createVerification } from "./createVerification";

export async function registerUser({
  options,
  prisma,
  config,
}: {
  options: {
    input: {
      username: string;
      email: string;
      password: string;
    };
    ipAddress?: string;
  };
  prisma: PrismaClient;
  config: Required<AegisAuthConfig>;
}): Promise<ActionResponse<{ user: ClientUser }>> {
  try {
    const { input, ipAddress } = options;

    if (config.rateLimiting.register.enabled && ipAddress) {
      const limiter = createRouteLimiter({ routeKey: "register", config });
      const limit = await limitIpAttempts({ ipAddress, rateLimiter: limiter });
      if (!limit.success) {
        config.logger.securityEvent("RATE_LIMIT_EXCEEDED", {
          route: "register",
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

    const credentials = registerSchema.safeParse(input);
    if (!credentials.success) {
      config.logger.securityEvent("INVALID_INPUT", {
        route: "register",
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

    const existingUser = (await prisma.user.findFirst({
      where: {
        OR: [{ username: input.username }, { email: input.email }],
      },
    })) as PrismaUser | null;

    if (existingUser) {
      config.logger.securityEvent("DUPLICATE_USER", {
        route: "register",
        ipAddress,
        ...input,
      });
      return {
        success: false,
        status: 409,
        message: "User already exists",
        code: ErrorCodes.DUPLICATE_USER,
      };
    }

    const hashedPassword = await hashPassword({
      password: credentials.data.password,
      config,
    });

    const user = (await prisma.user.create({
      data: {
        username: credentials.data.username,
        email: credentials.data.email,
        password: hashedPassword,
        isEmailVerified: !config.accountSecurity.requireEmailVerification,
      },
    })) as PrismaUser;

    if (config.accountSecurity.requireEmailVerification) {
      const verification = await createVerification({
        options: {
          userId: user.id,
          type: VerificationType.EMAIL_VERIFICATION,
        },
        prisma,
        config,
      });

      if (!verification.success || !verification.data?.verification) {
        return {
          success: false,
          status: 500,
          message: "Failed to create verification",
          code: ErrorCodes.INTERNAL_SERVER_ERROR,
        };
      }

      const { token } = verification.data.verification;
      await sendVerificationEmail({ toEmail: user.email, token, config });
    }

    config.logger.securityEvent("USER_REGISTERED", {
      userId: user.id,
      ipAddress,
    });

    const clientUser = clientSafeUser({ user });

    return {
      success: true,
      status: 201,
      message: "User registered",
      data: { user: clientUser },
    };
  } catch (err) {
    config.logger.error("Unexpected error in registerUser", { error: err });
    return {
      success: false,
      status: 500,
      message: "Internal Server Error",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
