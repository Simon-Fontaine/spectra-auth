export interface AegisError {
  code: string;
  message: string;
}

export type AegisResponse<T> =
  | {
      success: true;
      data: T;
      error: null;
    }
  | {
      success: false;
      data: null;
      error: AegisError;
    };
