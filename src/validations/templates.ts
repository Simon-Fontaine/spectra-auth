import { z } from "zod";
import type { PasswordConfig } from "../types";

const validationMessages = {
  required: (field: string) => `${field} is required.`,
  length: {
    min: (field: string, length: number) =>
      `${field} must be at least ${length} characters long.`,
    max: (field: string, length: number) =>
      `${field} must not exceed ${length} characters.`,
  },
  format: {
    email: "Please provide a valid email address.",
    username:
      "Username must be lowercase and may only contain letters, numbers, and underscores.",
    displayName:
      "Display name may only contain letters, numbers, underscores, and spaces.",
    password:
      "Password must include at least one uppercase letter, one lowercase letter, one number, and one special character.",
  },
  password: {
    match: "Passwords do not match.",
  },
};

function buildPasswordRegex(policy: PasswordConfig["rules"]): RegExp {
  let pattern = "^";
  if (policy.requireLowercase) {
    pattern += "(?=.*[a-z])";
  }
  if (policy.requireUppercase) {
    pattern += "(?=.*[A-Z])";
  }
  if (policy.requireNumber) {
    pattern += "(?=.*\\d)";
  }
  if (policy.requireSymbol) {
    pattern += "(?=.*[\\W_])";
  }
  pattern += `.{${policy.minLength},${policy.maxLength}}$`;
  return new RegExp(pattern);
}

const createStringSchema = (options: {
  field: string;
  minLength?: number;
  maxLength?: number;
  regex?: RegExp;
  regexMessage?: string;
}) => {
  const { field, minLength, maxLength, regex, regexMessage } = options;

  let schema = z.string({ required_error: validationMessages.required(field) });

  if (minLength !== undefined) {
    schema = schema.min(minLength, {
      message: validationMessages.length.min(field, minLength),
    });
  }

  if (maxLength !== undefined) {
    schema = schema.max(maxLength, {
      message: validationMessages.length.max(field, maxLength),
    });
  }

  if (regex) {
    schema = schema.regex(regex, {
      message: regexMessage || `${field} is in an invalid format.`,
    });
  }

  return schema.transform((val) => val.trim());
};

export const getPasswordSchema = (
  type: "Password" | "ConfirmPassword",
  policy: PasswordConfig["rules"],
) => {
  const regex = buildPasswordRegex(policy);

  return z
    .string({
      required_error: `${type} is required.`,
    })
    .min(policy.minLength, {
      message: `${type} must be at least ${policy.minLength} characters long.`,
    })
    .max(policy.maxLength, {
      message: `${type} must not exceed ${policy.maxLength} characters.`,
    })
    .regex(regex, {
      message: `${type} does not meet the complexity requirements (must include uppercase, lowercase, digit, and special character).`,
    })
    .transform((val) => val.trim());
};

export const getEmailSchema = () =>
  z
    .string()
    .min(1, { message: validationMessages.length.min("Email", 1) })
    .email({ message: validationMessages.format.email })
    .transform((val) => val.trim());

export const getUsernameSchema = () =>
  createStringSchema({
    field: "Username",
    minLength: 1,
    maxLength: 48,
    regex: /^[a-z0-9_]+$/,
    regexMessage: validationMessages.format.username,
  });

export const getDisplayNameSchema = () =>
  createStringSchema({
    field: "Display name",
    maxLength: 48,
    regex: /^[a-zA-Z0-9_ ]*$/,
    regexMessage: validationMessages.format.displayName,
  }).optional();

export const getAvatarUrlSchema = () =>
  z
    .string()
    .url({ message: "Avatar URL must be a valid URL." })
    .transform((val) => val.trim())
    .optional();
