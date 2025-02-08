import type { SpectraAuthConfig } from "../config";

export async function sendPasswordResetEmail({
  toEmail,
  token,
  config,
}: { toEmail: string; token: string; config: Required<SpectraAuthConfig> }) {
  config.logger.debug(
    `[Mock] Password reset link to ${toEmail}: /reset-password?token=${token}`,
    {
      email: toEmail,
      token,
    },
  );
}
