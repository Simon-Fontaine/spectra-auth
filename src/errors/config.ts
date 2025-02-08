import { ErrorCodes } from "../types/errorCodes";

export class ConfigurationError extends Error {
  status: number;
  code: ErrorCodes;

  constructor(
    message = "Invalid configuration provided",
    status = 500,
    code = ErrorCodes.CONFIGURATION_ERROR,
  ) {
    super(message);
    this.name = "ConfigurationError";
    this.status = status;
    this.code = code;
    Object.setPrototypeOf(this, ConfigurationError.prototype);
  }
}
