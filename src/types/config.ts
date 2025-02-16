import type { z } from "zod";
import type { configSchema } from "../config";

export type AegisAuthConfig = z.infer<typeof configSchema>;
