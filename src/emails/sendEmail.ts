import { Resend } from "resend";
import type { SpectraAuthConfig } from "../config";

export interface ResendEmailOptions {
  from: string;
  to: string;
  subject: string;
  react: React.ReactNode;
  config: Required<SpectraAuthConfig>;
}

export async function sendEmailWithResend(options: ResendEmailOptions) {
  const { config, ...emailOptions } = options;
  if (!config.email || !config.email.resendApiKey) {
    throw new Error("Resend API key is not configured in your email settings.");
  }

  const resend = new Resend(config.email.resendApiKey);

  const payload = {
    ...emailOptions,
    html:
      typeof emailOptions.react === "string" ? emailOptions.react : undefined,
    react:
      typeof emailOptions.react !== "string" ? emailOptions.react : undefined,
  };

  return await resend.emails.send(payload);
}
