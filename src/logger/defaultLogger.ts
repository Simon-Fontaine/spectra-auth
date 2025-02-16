import type { AegisLogger } from "../types";

export const defaultLogger: AegisLogger = {
  info(msg, meta) {
    console.info(`[INFO] ${msg}`, meta);
  },
  warn(msg, meta) {
    console.warn(`[WARN] ${msg}`, meta);
  },
  error(msg, meta) {
    console.error(`[ERROR] ${msg}`, meta);
  },
};
