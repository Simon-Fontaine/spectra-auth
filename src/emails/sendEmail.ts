import { Resend } from "resend";
import type { AegisAuthConfig } from "../config";

export interface SendEmailOptions {
  from?: string;
  to: string | string[];
  subject: string;
  html: string;
  config: AegisAuthConfig;
}

export async function sendEmail(options: SendEmailOptions) {
  const { config, ...emailOptions } = options;

  if (!config.email || !config.email.resendApiKey) {
    throw new Error("Resend API key is not configured in your email settings.");
  }

  const resend = new Resend(config.email.resendApiKey);

  try {
    const from = emailOptions.from ?? config.email.from;
    if (!from) {
      throw new Error("No from email is setup.");
    }

    const data = await resend.emails.send({
      from,
      to: Array.isArray(emailOptions.to) ? emailOptions.to : [emailOptions.to],
      subject: emailOptions.subject,
      html: emailOptions.html,
    });

    return data;
  } catch (error) {
    config.logger.error("Failed to send email", { error });
    throw error;
  }
}
