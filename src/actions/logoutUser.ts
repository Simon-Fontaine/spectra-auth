import type { PrismaClient } from "@prisma/client";
import type { AegisAuthConfig } from "../config";
import type { ActionResponse } from "../types";
import { revokeSession } from "./revokeSession";

export async function logoutUser({
  sessionToken,
  prisma,
  config,
}: {
  sessionToken: string;
  prisma: PrismaClient;
  config: Required<AegisAuthConfig>;
}): Promise<ActionResponse> {
  const result = await revokeSession({
    options: { input: { sessionToken } },
    prisma,
    config,
  });

  if (!result.success) {
    return result;
  }

  return {
    success: true,
    status: 200,
    message: "User logged out",
  };
}
