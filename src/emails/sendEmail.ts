import { Resend } from "resend";
import type { CoreContext } from "../types";

export interface SendEmailOptions {
  from?: string;
  to: string | string[];
  subject: string;
  html: string;
}

export async function sendEmail(ctx: CoreContext, options: SendEmailOptions) {
  const { logger, communication } = ctx.config;
  const { email } = communication;

  if (!email || !email.resendApiKey) {
    throw new Error("Resend API key is not configured in your email settings.");
  }

  const resend = new Resend(email.resendApiKey);

  try {
    const from = options.from ?? email.from;
    if (!from) {
      throw new Error("No from email is setup.");
    }

    const data = await resend.emails.send({
      from,
      to: Array.isArray(options.to) ? options.to : [options.to],
      subject: options.subject,
      html: options.html,
    });

    return data;
  } catch (error) {
    logger.error("Failed to send email", { error });
    throw error;
  }
}
