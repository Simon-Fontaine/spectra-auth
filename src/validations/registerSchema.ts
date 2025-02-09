import { z } from "zod";
import {
  getEmailSchema,
  getPasswordSchema,
  getUsernameSchema,
} from "./templates";

export const registerSchema = z.object({
  username: getUsernameSchema(),
  email: getEmailSchema(),
  password: getPasswordSchema("Password"),
});
