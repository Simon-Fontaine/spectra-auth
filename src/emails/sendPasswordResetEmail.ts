import type { SpectraAuthConfig } from "../config";
import { sendEmailWithResend } from "./sendEmail";

export async function sendPasswordResetEmail({
  toEmail,
  token,
  config,
}: {
  toEmail: string;
  token: string;
  config: Required<SpectraAuthConfig>;
}) {
  const { email } = config;
  let emailContent: React.ReactNode;

  if (email?.templates?.passwordReset) {
    emailContent = await email.templates.passwordReset({ token, toEmail });
  } else {
    emailContent = `
      <html>
        <body>
          <p>You requested a password reset. Click the link below to reset your password:</p>
          <a href="https://yourapp.com/reset-password?token=${token}">Reset Password</a>
        </body>
      </html>
    `;
  }

  const subject = "Reset your password";
  const from = email?.from || "no-reply@example.com";

  try {
    const result = await sendEmailWithResend({
      from,
      to: toEmail,
      subject,
      react: emailContent,
      config,
    });
    config.logger.info("Password reset email sent", { toEmail, result });
  } catch (error) {
    config.logger.error("Failed to send password reset email", {
      toEmail,
      error,
    });
    throw error;
  }
}
