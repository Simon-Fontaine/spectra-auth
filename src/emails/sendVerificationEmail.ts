import type { CoreContext } from "../types";
import { sendEmail } from "./sendEmail";

interface VerificationEmailOptions {
  toEmail: string;
  token: string;
  type: string;
  callbackUrl?: string;
}

export async function sendVerificationEmail(
  ctx: CoreContext,
  options: VerificationEmailOptions,
) {
  const { logger, communication, core } = ctx.config;
  const { email } = communication;

  const { toEmail, token, type } = options;

  const callbackUrl =
    options.callbackUrl || `${core.baseUrl}/verify?token=${token}`;
  const template = email.templates[type];

  let subject: string;
  let html: string;

  if (template) {
    subject = template.subject({ token, toEmail, callbackUrl });
    html = template.html({ token, toEmail, callbackUrl });
  } else {
    subject = `Please complete verification: ${type}`;
    html = `
      <p>You requested <b>${type}</b>. Please use this token:</p>
      <p><code>${token}</code></p>
      <p>Or click <a href="${callbackUrl}">here</a> to proceed.</p>
    `;
  }

  try {
    const result = await sendEmail(ctx, {
      to: toEmail,
      subject,
      html,
    });
    logger.info(`Email sent for ${type}`, { toEmail, result });
    return { success: true, result };
  } catch (error) {
    logger.error(`Failed to send ${type} email`, { toEmail, error });
    return { success: false, error };
  }
}
