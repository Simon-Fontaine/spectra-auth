import { createVerificationToken } from "../security";
import {
  type ActionResponse,
  type CoreContext,
  ErrorCodes,
  type PrismaVerification,
  type VerificationType,
} from "../types";
import { createTime } from "../utils";
import { createVerificationSchema } from "../validations";

export async function createVerification(
  context: CoreContext,
  input: {
    userId: string;
    type: VerificationType;
    tokenExpirySeconds?: number;
  },
): Promise<ActionResponse<{ verification: PrismaVerification }>> {
  const { prisma, config } = context;

  try {
    const validatedInput = createVerificationSchema.safeParse(input);
    if (!validatedInput.success) {
      return {
        success: false,
        status: 400,
        message: "Invalid input provided",
        code: ErrorCodes.INVALID_INPUT,
        data: null,
      };
    }

    const { userId, type, tokenExpirySeconds } = validatedInput.data;

    const verificationToken = await createVerificationToken({ config });
    const expiresAt = createTime(
      tokenExpirySeconds || config.verification.tokenExpirySeconds,
      "s",
    ).getDate();

    const verification = (await prisma.verification.create({
      data: {
        token: verificationToken,
        expiresAt,
        type: type,
        userId: userId,
      },
    })) as PrismaVerification;

    config.logger.securityEvent("VERIFICATION_CREATED", {
      verificationId: verification.id,
      userId: verification.userId,
      type: verification.type,
    });

    return {
      success: true,
      status: 200,
      message: "Verification created",
      data: { verification },
    };
  } catch (error) {
    config.logger.error("Error creating verification", {
      error,
      userId: input.userId,
    });
    return {
      success: false,
      status: 500,
      message: "An unexpected error occurred.",
      code: ErrorCodes.INTERNAL_SERVER_ERROR,
    };
  }
}
