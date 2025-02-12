import type { AegisAuthConfig } from "../config";
import { type SendEmailOptions, sendEmail } from "./sendEmail";

interface VerificationEmailOptions {
  toEmail: string;
  token: string;
  config: AegisAuthConfig;
}

export async function sendVerificationEmail(options: VerificationEmailOptions) {
  const { toEmail, token, config } = options;
  let html: string;

  if (config.email?.templates?.verification) {
    html = config.email.templates.verification({ token, toEmail });
  } else {
    html = `
      <html>
        <body>
          <p>Please verify your email address by clicking the link below:</p>
          <a href="${config.email?.baseUrl}/verify-email?token=${token}">Verify Email</a>
        </body>
      </html>
    `;
  }

  const sendOption: SendEmailOptions = {
    to: toEmail,
    subject: "Verify your email",
    html: html,
    config: config,
  };

  try {
    const result = await sendEmail(sendOption);
    config.logger.info("Verification email sent", { toEmail, result });
    return result;
  } catch (error) {
    config.logger.error("Failed to send verification email", {
      toEmail,
      error,
    });
    throw error;
  }
}
