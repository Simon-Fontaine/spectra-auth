import { Time } from "../constants";

type TimeUnit = "ms" | "s" | "m" | "h" | "d" | "w" | "mo" | "y";
type TimeValue = `${number}${TimeUnit}`;

/**
 * Time utility for handling durations and timestamps
 */
export interface TimeObject {
  readonly value: number;
  readonly unit: TimeUnit;
  toMilliseconds(): number;
  toSeconds(): number;
  toMinutes(): number;
  toHours(): number;
  toDays(): number;
  toWeeks(): number;
  toMonths(): number;
  toYears(): number;
  getDate(from?: Date): Date;
  add(other: TimeObject | TimeValue | number): TimeObject;
  subtract(other: TimeObject | TimeValue | number): TimeObject;
  multiply(factor: number): TimeObject;
  divide(divisor: number): TimeObject;
  equals(other: TimeObject | TimeValue | number): boolean;
  lessThan(other: TimeObject | TimeValue | number): boolean;
  greaterThan(other: TimeObject | TimeValue | number): boolean;
  format(options?: Intl.RelativeTimeFormatOptions): string;
  fromNow(options?: Intl.RelativeTimeFormatOptions): string;
  ago(options?: Intl.RelativeTimeFormatOptions): string;
}

/**
 * Creates a TimeObject from a value and unit
 *
 * @param value - Numeric value
 * @param unit - Time unit
 * @returns A TimeObject instance
 */
export function createTime(value: number, unit: TimeUnit = "ms"): TimeObject {
  const convertToMs = (val: number, u: TimeUnit): number => {
    switch (u) {
      case "ms":
        return val;
      case "s":
        return val * Time.SECOND;
      case "m":
        return val * Time.MINUTE;
      case "h":
        return val * Time.HOUR;
      case "d":
        return val * Time.DAY;
      case "w":
        return val * Time.WEEK;
      case "mo":
        return val * Time.MONTH;
      case "y":
        return val * Time.YEAR;
    }
  };

  const ms = convertToMs(value, unit);

  const normalize = (other: TimeObject | TimeValue | number): number => {
    if (typeof other === "number") {
      return other; // Assume milliseconds
    }
    if (typeof other === "string") {
      return parseTime(other).toMilliseconds();
    }
    return other.toMilliseconds();
  };

  const timeObject: TimeObject = {
    value,
    unit,

    toMilliseconds: () => ms,
    toSeconds: () => ms / Time.SECOND,
    toMinutes: () => ms / Time.MINUTE,
    toHours: () => ms / Time.HOUR,
    toDays: () => ms / Time.DAY,
    toWeeks: () => ms / Time.WEEK,
    toMonths: () => ms / Time.MONTH,
    toYears: () => ms / Time.YEAR,

    getDate: (from = new Date()) => new Date(from.getTime() + ms),

    add: (other) => createTime(ms + normalize(other), "ms"),
    subtract: (other) => createTime(ms - normalize(other), "ms"),
    multiply: (factor) => createTime(ms * factor, "ms"),
    divide: (divisor) => createTime(ms / divisor, "ms"),

    equals: (other) => ms === normalize(other),
    lessThan: (other) => ms < normalize(other),
    greaterThan: (other) => ms > normalize(other),

    format: (options) => {
      // Implementation using Intl.RelativeTimeFormat
      const formatter = new Intl.RelativeTimeFormat("en", options);

      if (Math.abs(ms) < Time.MINUTE) {
        return formatter.format(Math.round(ms / Time.SECOND), "seconds");
      }
      if (Math.abs(ms) < Time.HOUR) {
        return formatter.format(Math.round(ms / Time.MINUTE), "minutes");
      }
      if (Math.abs(ms) < Time.DAY) {
        return formatter.format(Math.round(ms / Time.HOUR), "hours");
      }
      if (Math.abs(ms) < Time.WEEK) {
        return formatter.format(Math.round(ms / Time.DAY), "days");
      }
      if (Math.abs(ms) < Time.MONTH) {
        return formatter.format(Math.round(ms / Time.WEEK), "weeks");
      }
      if (Math.abs(ms) < Time.YEAR) {
        return formatter.format(Math.round(ms / Time.MONTH), "months");
      }
      return formatter.format(Math.round(ms / Time.YEAR), "years");
    },

    fromNow: (options) => {
      if (ms >= 0) {
        return timeObject.format(options);
      }
      return timeObject.multiply(-1).ago(options);
    },

    ago: (options) => {
      if (ms >= 0) {
        return timeObject.multiply(-1).format(options);
      }
      return timeObject.multiply(-1).fromNow(options);
    },
  };

  return timeObject;
}

/**
 * Parses a time string like "30d" or "2h" into a TimeObject
 *
 * @param timeString - String in the format "{number}{unit}"
 * @returns A TimeObject instance
 */
export function parseTime(timeString: TimeValue): TimeObject {
  const match = /^(\d+)(ms|s|m|h|d|w|mo|y)$/.exec(timeString);
  if (!match) {
    throw new Error(
      `Invalid time string format: ${timeString}. Expected format like "30d" or "2h".`,
    );
  }

  const value = Number.parseInt(match[1], 10);
  const unit = match[2] as TimeUnit;

  return createTime(value, unit);
}

/**
 * Adjusts a date by adding the specified amount of time
 *
 * @param date - Base date
 * @param amount - Amount of time to add
 * @param unit - Time unit
 * @returns A new date with the added time
 */
export function addTime(date: Date, amount: number, unit: TimeUnit): Date {
  return createTime(amount, unit).getDate(date);
}

/**
 * Checks if a date is expired (before current time)
 *
 * @param date - Date to check
 * @returns True if the date is in the past
 */
export function isExpired(date: Date): boolean {
  return date.getTime() < Date.now();
}

/**
 * Calculates time remaining until a future date
 *
 * @param date - Future date
 * @returns TimeObject representing the remaining time
 */
export function timeUntil(date: Date): TimeObject {
  const remaining = date.getTime() - Date.now();
  return createTime(remaining, "ms");
}
