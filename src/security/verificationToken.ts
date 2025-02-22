import type { AegisAuthConfig } from "../types";
import type { AegisResponse } from "../types";
import { fail, success } from "../utils/response";
import { hex } from "./hex";
import { randomBytes } from "./random";

export async function createVerificationToken({
  config,
}: {
  config: AegisAuthConfig;
}): Promise<AegisResponse<string>> {
  try {
    const bytesResponse = randomBytes(config.verification.tokenLength);
    if (!bytesResponse.success) {
      return fail(
        "VERIFICATION_TOKEN_BYTES_ERROR",
        bytesResponse.error.message,
      );
    }

    const verificationToken = hex.encode(bytesResponse.data);
    return success(verificationToken);
  } catch (error) {
    return fail(
      "VERIFICATION_TOKEN_ERROR",
      "Failed to create verification token",
    );
  }
}
