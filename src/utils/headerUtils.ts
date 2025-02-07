/**
 * Sets a cookie in the Set-Cookie header.
 *
 * @param res The response object.
 * @param cookieStr Serialized cookie string (from cookie.serialize).
 */
export function setCookieHeader(res: Response, cookieStr: string): void {
  const existingHeader = res.headers.get("Set-Cookie");
  if (existingHeader) {
    res.headers.set(
      "Set-Cookie",
      Array.isArray(existingHeader)
        ? [...existingHeader, cookieStr].join(", ")
        : [existingHeader, cookieStr].join(", "),
    );
  } else {
    res.headers.set("Set-Cookie", cookieStr);
  }
}
