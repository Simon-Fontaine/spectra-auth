import type { SpectraAuthConfig } from "../config";
import { sendEmailWithResend } from "./sendEmail";

export async function sendVerificationEmail({
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

  if (email?.templates?.verification) {
    emailContent = await email.templates.verification({ token, toEmail });
  } else {
    emailContent = `
      <html>
        <body>
          <p>Please verify your email address by clicking the link below:</p>
          <a href="https://yourapp.com/verify-email?token=${token}">Verify Email</a>
        </body>
      </html>
    `;
  }

  const subject = "Verify your email";
  const from = email?.from || "no-reply@example.com";

  try {
    const result = await sendEmailWithResend({
      from,
      to: toEmail,
      subject,
      react: emailContent,
      config,
    });
    config.logger.info("Verification email sent", { toEmail, result });
  } catch (error) {
    config.logger.error("Failed to send verification email", {
      toEmail,
      error,
    });
    throw error;
  }
}
