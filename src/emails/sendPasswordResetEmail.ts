import type { AegisAuthConfig } from "../config";
import { type SendEmailOptions, sendEmail } from "./sendEmail";

interface PasswordResetEmailOptions {
  toEmail: string;
  token: string;
  config: AegisAuthConfig;
}

export async function sendPasswordResetEmail(
  options: PasswordResetEmailOptions,
) {
  const { toEmail, token, config } = options;
  let html: string;

  if (config.email?.templates?.passwordReset) {
    html = config.email.templates.passwordReset({ token, toEmail });
  } else {
    html = `
    <html>
      <body>
        <p>You requested a password reset. Click the link below to reset your password:</p>
        <a href="${config.email?.baseUrl}/reset-password?token=${token}">Reset Password</a>
      </body>
    </html>
    `;
  }

  const sendOption: SendEmailOptions = {
    to: toEmail,
    subject: "Reset your password",
    html: html,
    config: config,
  };

  try {
    const result = await sendEmail(sendOption);
    config.logger.info("Password reset email sent", { toEmail, result });
    return result;
  } catch (error) {
    config.logger.error("Failed to send password reset email", {
      toEmail,
      error,
    });
    throw error;
  }
}
