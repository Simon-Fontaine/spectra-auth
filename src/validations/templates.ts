import { z } from "zod";

// Enhanced validation messages with more descriptive language.
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

// Reusable schema factory that automatically trims input and validates length/format.
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

// Password schema that enforces a complexity requirement.
// The regex below ensures at least one lowercase, one uppercase, one digit, and one special character.
const passwordComplexityRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).+$/;
export const getPasswordSchema = (type: "Password" | "ConfirmPassword") =>
  createStringSchema({
    field: type,
    minLength: 8,
    maxLength: 32,
    regex: passwordComplexityRegex,
    regexMessage: validationMessages.format.password,
  });

// Email schema: also validates that the string is a valid email.
export const getEmailSchema = () =>
  z
    .string()
    .min(1, { message: validationMessages.length.min("Email", 1) })
    .email({ message: validationMessages.format.email })
    .transform((val) => val.trim());

// Username schema: enforces lowercase letters, numbers, and underscores only.
export const getUsernameSchema = () =>
  createStringSchema({
    field: "Username",
    minLength: 1,
    maxLength: 48,
    regex: /^[a-z0-9_]+$/,
    regexMessage: validationMessages.format.username,
  });

// Display name schema: only letters, numbers, underscores, and spaces; optional.
export const getDisplayNameSchema = () =>
  createStringSchema({
    field: "Display name",
    maxLength: 48,
    regex: /^[a-zA-Z0-9_ ]*$/,
    regexMessage: validationMessages.format.displayName,
  }).optional();

// Avatar URL schema: must be a valid URL if provided.
export const getAvatarUrlSchema = () =>
  z
    .string()
    .url({ message: "Avatar URL must be a valid URL." })
    .transform((val) => val.trim())
    .optional();
