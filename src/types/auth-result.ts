export interface SpectraAuthResult {
  error: boolean;
  status: number;
  message: string;
  code?: string;
  data?: Record<string, unknown>;
}
