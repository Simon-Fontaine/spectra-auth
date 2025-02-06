// function from: https://github.com/better-auth/utils

import { subtle } from "uncrypto";
import type { EncodingFormat, SHAFamily, TypedArray } from "../types";
import { base64, base64Url } from "./base64";
import { hex } from "./hex";

export const createHMAC = <E extends EncodingFormat = "none">(
  algorithm: SHAFamily = "SHA-256",
  encoding: E = "none" as E,
) => {
  const hmac = {
    importKey: async (
      key: string | ArrayBuffer | TypedArray,
      keyUsage: "sign" | "verify",
    ) => {
      return subtle.importKey(
        "raw",
        typeof key === "string" ? new TextEncoder().encode(key) : key,
        { name: "HMAC", hash: { name: algorithm } },
        false,
        [keyUsage],
      );
    },
    sign: async (
      hmacKey: string | CryptoKey,
      data: string | ArrayBuffer | TypedArray,
    ): Promise<E extends "none" ? ArrayBuffer : string> => {
      let actualKey: CryptoKey;
      if (typeof hmacKey === "string") {
        actualKey = await hmac.importKey(hmacKey, "sign");
      } else {
        actualKey = hmacKey;
      }

      const signature = await subtle.sign(
        "HMAC",
        actualKey,
        typeof data === "string" ? new TextEncoder().encode(data) : data,
      );

      type SignatureResult = E extends "none" ? ArrayBuffer : string;

      if (encoding === "hex") {
        return hex.encode(signature) as SignatureResult;
      }
      if (
        encoding === "base64" ||
        encoding === "base64url" ||
        encoding === "base64urlnopad"
      ) {
        return base64Url.encode(signature, {
          padding: encoding !== "base64urlnopad",
        }) as SignatureResult;
      }
      return signature as SignatureResult;
    },
    verify: async (
      hmacKey: CryptoKey | string,
      data: string | ArrayBuffer | TypedArray,
      signature: string | ArrayBuffer | TypedArray,
    ) => {
      let key = hmacKey;
      let sig = signature;
      if (typeof key === "string") {
        key = await hmac.importKey(key, "verify");
      }
      if (encoding === "hex") {
        sig = hex.decode(sig);
      }
      if (
        encoding === "base64" ||
        encoding === "base64url" ||
        encoding === "base64urlnopad"
      ) {
        sig = base64.decode(sig);
      }
      return subtle.verify(
        "HMAC",
        key,
        typeof sig === "string" ? new TextEncoder().encode(sig) : sig,
        typeof data === "string" ? new TextEncoder().encode(data) : data,
      );
    },
  };
  return hmac;
};
