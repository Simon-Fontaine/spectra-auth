import type { ErrorCodes } from "./errors";

export interface ActionResponse<T = unknown> {
  success: boolean;
  status: number;
  message: string;
  code?: ErrorCodes;
  data?: T | null;
}
