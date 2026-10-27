import { HttpError, reject } from "./errors.js";

export function parsePath(rawPath: string): { apiId: string; path: string; encodedPath: string } {
  reject(rawPath.startsWith("/") && !/[\\?#\x00-\x20\x7f]/.test(rawPath), 400, "invalid_path");
  const raw = rawPath.slice(1).split("/");
  reject(raw.length >= 1 && raw[0] !== "", 400, "invalid_path");
  const segments = raw.map((segment) => {
    let decoded: string;
    try { decoded = decodeURIComponent(segment); } catch { throw new HttpError(400, "invalid_path"); }
    reject(!/[\\/%?#\x00-\x20\x7f]/.test(decoded) && decoded !== "." && decoded !== "..", 400, "invalid_path");
    return decoded;
  });
  reject(segments.length <= 2 || segments.slice(1).every(Boolean), 400, "invalid_path");
  reject(/^[A-Za-z][A-Za-z0-9_-]*$/.test(segments[0]) && raw[0] === segments[0], 400, "invalid_path");
  const path = "/" + segments.slice(1).join("/");
  return { apiId: segments[0], path, encodedPath: "/" + segments.slice(1).map(encodeURIComponent).join("/") };
}

export function parseQuery(raw: string): Record<string, string> {
  reject(raw.length <= 32_768 && !/%(?![0-9a-f]{2})/i.test(raw) && !/[\x00-\x1f\x7f#]/.test(raw), 400, "invalid_query");
  try { decodeURIComponent(raw.replace(/\+/g, " ")); } catch { throw new HttpError(400, "invalid_query"); }
  const result: Record<string, string> = Object.create(null);
  for (const [key, value] of new URLSearchParams(raw)) {
    reject(key.length > 0 && !Object.hasOwn(result, key) &&
      !/[\x00-\x1f\x7f]/.test(key + value), 400, "ambiguous_query");
    result[key] = value;
  }
  return result;
}

// JSON.parse alone silently accepts duplicate keys, including escaped duplicates.
export function parseJson(text: string): unknown {
  let position = 0;
  let nodes = 0;
  const space = () => { while (/[ \t\r\n]/.test(text[position] ?? "") && position < text.length) position++; };
  function string(): string {
    const start = position++;
    while (position < text.length) {
      const character = text[position++];
      if (character === "\\") position++;
      else if (character === '"') return JSON.parse(text.slice(start, position)) as string;
    }
    throw new Error("invalid");
  }
  function value(depth: number): unknown {
    if (depth > 64 || ++nodes > 50_000) throw new Error("limit");
    space();
    const character = text[position];
    if (character === '"') return string();
    if (character === "{") {
      position++;
      space();
      const object: Record<string, unknown> = Object.create(null);
      if (text[position] === "}") { position++; return object; }
      while (position < text.length) {
        space();
        if (text[position] !== '"') throw new Error("key");
        const key = string();
        if (Object.hasOwn(object, key) || ["__proto__", "constructor", "prototype"].includes(key)) throw new Error("duplicate");
        space();
        if (text[position++] !== ":") throw new Error("colon");
        object[key] = value(depth + 1);
        space();
        const delimiter = text[position++];
        if (delimiter === "}") return object;
        if (delimiter !== ",") throw new Error("comma");
      }
      throw new Error("object");
    }
    if (character === "[") {
      position++;
      space();
      const array: unknown[] = [];
      if (text[position] === "]") { position++; return array; }
      while (position < text.length) {
        array.push(value(depth + 1));
        space();
        const delimiter = text[position++];
        if (delimiter === "]") return array;
        if (delimiter !== ",") throw new Error("comma");
      }
      throw new Error("array");
    }
    const match = /^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(text.slice(position));
    if (!match) throw new Error("value");
    position += match[0].length;
    const primitive: unknown = JSON.parse(match[0]);
    if (typeof primitive === "number" && (!Number.isFinite(primitive) ||
      (Number.isInteger(primitive) && !Number.isSafeInteger(primitive)))) throw new Error("number");
    return primitive;
  }
  try {
    const result = value(0);
    space();
    if (position !== text.length) throw new Error("trailing");
    return result;
  } catch {
    throw new HttpError(400, "invalid_json");
  }
}
