import { getRandomValues } from "uncrypto";
import type { AegisResponse } from "../types";
import { fail, success } from "../utils/response";

export function randomBytes(length: number): AegisResponse<Uint8Array> {
  try {
    const arr = getRandomValues(new Uint8Array(length));
    return success(arr);
  } catch (error) {
    return fail("RANDOM_BYTES_ERROR", "Failed to generate random bytes");
  }
}
