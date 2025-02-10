import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import type { ActionResponse } from "../types";
import { revokeSession } from "./revokeSession";

export async function logoutUser(
  context: {
    prisma: PrismaClient;
    config: Required<AegisAuthConfig>;
  },
  input: {
    sessionToken: string;
  },
): Promise<ActionResponse> {
  const result = await revokeSession(context, input);

  if (!result.success) {
    return result;
  }

  return {
    success: true,
    status: 200,
    message: "User logged out",
  };
}
