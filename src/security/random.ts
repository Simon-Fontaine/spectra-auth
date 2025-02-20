import { getRandomValues } from "uncrypto";

export function randomBytes(length: number): Uint8Array {
  return getRandomValues(new Uint8Array(length));
}
