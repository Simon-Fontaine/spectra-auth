import type { SpectraAuthConfig } from "../config";

export async function sendVerificationEmail({
  toEmail,
  token,
  config,
}: { toEmail: string; token: string; config: Required<SpectraAuthConfig> }) {
  config.logger.debug(
    `[Mock] Verification link to ${toEmail}: /verify-email?token=${token}`,
    {
      email: toEmail,
      token,
    },
  );
}
