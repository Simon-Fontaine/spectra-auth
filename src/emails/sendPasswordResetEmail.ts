import type { CoreContext } from "../types";
import { type SendEmailOptions, sendEmail } from "./sendEmail";

export async function sendPasswordResetEmail(
  ctx: CoreContext,
  options: {
    toEmail: string;
    token: string;
    callbackUrl?: string;
  },
) {
  const { toEmail, token, callbackUrl } = options;
  const { communication, core, logger } = ctx.config;
  const { email } = communication;

  let html: string;
  const url = callbackUrl || `${core.baseUrl}/reset-password/?token=`;

  if (email.templates.passwordReset) {
    html = email.templates.passwordReset({ token, toEmail, callbackUrl: url });
  } else {
    html = `
    <html>
      <body>
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${url}${token}">Reset Password</a>
      </body>
    </html>
    `;
  }

  const sendOption: SendEmailOptions = {
    to: toEmail,
    subject: "Reset your password",
    html: html,
  };

  try {
    const result = await sendEmail(ctx, sendOption);
    logger.info("Password reset email sent", { toEmail, result });
    return result;
  } catch (error) {
    logger.error("Failed to send password reset email", {
      toEmail,
      error,
    });
    throw error;
  }
}
