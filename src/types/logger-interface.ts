export interface LoggerInterface {
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
  securityEvent: (eventType: string, meta: Record<string, unknown>) => void;
}
