// function from: https://github.com/better-auth/utils

import type { TypedArray } from "../types";

const hexadecimal = "0123456789abcdef";
export const hex = {
  encode: (data: string | ArrayBuffer | TypedArray) => {
    const inputData =
      typeof data === "string" ? new TextEncoder().encode(data) : data;
    if (inputData.byteLength === 0) {
      return "";
    }
    const buffer = new Uint8Array(inputData);
    let result = "";
    for (const byte of buffer) {
      result += byte.toString(16).padStart(2, "0");
    }
    return result;
  },
  decode: (data: string | ArrayBuffer | TypedArray) => {
    if (!data) {
      return "";
    }
    if (typeof data === "string") {
      if (data.length % 2 !== 0) {
        throw new Error("Invalid hexadecimal string");
      }
      if (!new RegExp(`^[${hexadecimal}]+$`).test(data)) {
        throw new Error("Invalid hexadecimal string");
      }
      const result = new Uint8Array(data.length / 2);
      for (let i = 0; i < data.length; i += 2) {
        result[i / 2] = Number.parseInt(data.slice(i, i + 2), 16);
      }
      return new TextDecoder().decode(result);
    }
    return new TextDecoder().decode(data);
  },
};

export function decodeHexToBytes(hexStr: string): Uint8Array {
  if (hexStr.length % 2 !== 0) {
    throw new Error("Invalid hex string");
  }
  const bytes = new Uint8Array(hexStr.length / 2);
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes[i / 2] = Number.parseInt(hexStr.substring(i, i + 2), 16);
  }
  return bytes;
}
