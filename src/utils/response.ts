import type { AegisResponse } from "../types";

export function success<T>(data: T): AegisResponse<T> {
  return {
    success: true,
    data,
    error: null,
  };
}

export function fail<T>(code: string, message: string): AegisResponse<T> {
  return {
    success: false,
    data: null,
    error: {
      code,
      message,
    },
  };
}
