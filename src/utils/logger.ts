import { LogLevel } from "../types";

export class ConsoleLogger {
  private logLevel = LogLevel.Info;

  constructor(level?: LogLevel) {
    if (level) {
      this.logLevel = level;
    }
  }

  debug(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.Debug)) {
      this.logWithLevel(LogLevel.Debug, message, context);
    }
  }

  info(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.Info)) {
      this.logWithLevel(LogLevel.Info, message, context);
    }
  }

  warn(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.Warn)) {
      this.logWithLevel(LogLevel.Warn, message, context);
    }
  }

  error(message: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.Error)) {
      this.logWithLevel(LogLevel.Error, message, context);
    }
  }

  securityEvent(eventName: string, context?: Record<string, unknown>): void {
    if (this.shouldLog(LogLevel.Security)) {
      this.logWithLevel(LogLevel.Security, eventName, context);
    }
  }

  private shouldLog(level: LogLevel): boolean {
    const currentLevelValue = this.getLogLevelValue(this.logLevel);
    const messageLevelValue = this.getLogLevelValue(level);
    return messageLevelValue >= currentLevelValue;
  }

  private getLogLevelValue(level: LogLevel): number {
    switch (level) {
      case LogLevel.Debug:
        return 1;
      case LogLevel.Info:
        return 2;
      case LogLevel.Warn:
        return 3;
      case LogLevel.Error:
        return 4;
      case LogLevel.Security:
        return 5; // Security events are most important
      default:
        return 2; // Info level by default if unknown
    }
  }

  private logWithLevel(
    level: LogLevel,
    message: string,
    context?: Record<string, unknown>,
  ): void {
    let logMessage = `[SpectraAuth - ${level.toUpperCase()}] ${message}`;
    if (context) {
      logMessage += ` - Context: ${JSON.stringify(context)}`;
    }

    switch (level) {
      case LogLevel.Error:
        console.error(logMessage);
        break;
      case LogLevel.Warn:
        console.warn(logMessage);
        break;
      default:
        console.log(logMessage);
        break;
    }
  }
}
