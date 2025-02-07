import type { LoggerInterface } from "../types";

/**
 * Centralized security logger class. Wraps a LoggerInterface to handle security events.
 */
export class SecurityLogger {
  private logger: LoggerInterface;

  constructor(logger: LoggerInterface) {
    this.logger = logger;
  }

  /**
   * Logs a security-related event.
   * @param eventType A descriptive string for the event type (e.g., 'login-success', 'csrf-validation-failure').
   * @param meta Metadata associated with the event (user ID, IP address, etc.).
   */
  securityEvent(eventType: string, meta: Record<string, unknown>): void {
    this.logger.securityEvent(eventType, meta);
  }

  /**
   * Logs an informational message.
   * @param msg The message to log.
   * @param meta Optional metadata.
   */
  info(msg: string, meta?: Record<string, unknown>): void {
    this.logger.info(msg, meta);
  }

  /**
   * Logs a warning message.
   * @param msg The message to log.
   * @param meta Optional metadata.
   */
  warn(msg: string, meta?: Record<string, unknown>): void {
    this.logger.warn(msg, meta);
  }

  /**
   * Logs an error message.
   * @param msg The message to log.
   * @param meta Optional metadata.
   */
  error(msg: string, meta?: Record<string, unknown>): void {
    this.logger.error(msg, meta);
  }
}
