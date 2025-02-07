export enum LogLevel {
  Debug = "debug",
  Info = "info",
  Warn = "warn",
  Error = "error",
  Security = "security",
}
// export type LogLevel = keyof typeof LogLevelEnum;
export interface LoggerInterface {
  debug: (msg: string, meta?: Record<string, unknown>) => void;
  info: (msg: string, meta?: Record<string, unknown>) => void;
  warn: (msg: string, meta?: Record<string, unknown>) => void;
  error: (msg: string, meta?: Record<string, unknown>) => void;
  securityEvent: (eventType: string, meta: Record<string, unknown>) => void;
}
