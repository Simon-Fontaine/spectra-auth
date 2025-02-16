import type {
  ClientSession,
  ClientUser,
  PrismaSession,
  PrismaUser,
} from "../types";

export function transformUser({ user }: { user: PrismaUser }): ClientUser {
  const { password, ...safeUser } = user;
  return safeUser;
}

export function transformSession({
  session,
  sessionToken,
  csrfToken,
}: {
  session: PrismaSession;
  sessionToken: string;
  csrfToken?: string;
}): ClientSession {
  const { csrfTokenHash, tokenHash, ...safeSession } = session;
  const clientSession = {
    ...safeSession,
    sessionToken,
    csrfToken,
  };
  return clientSession;
}
