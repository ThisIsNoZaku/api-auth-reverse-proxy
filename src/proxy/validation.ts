import { isDeepStrictEqual } from "node:util";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { compileSchema, type Schema } from "../policies/schema.js";
import type { PolicyContext } from "../policies/engine.js";
import type { Api, Route } from "../registry/index.js";
import { unsafeHeaders } from "../registry/index.js";
import { reject } from "./errors.js";
import { parseJson, parseQuery } from "./parsing.js";

export interface ValidatedRequest {
  context: PolicyContext;
  body?: Buffer;
  rawQuery: string;
}

function typed(value: string, schema?: Schema): unknown {
  if (!schema) return value;
  let input: unknown = value;
  if (schema.type === "number" || schema.type === "integer") {
    reject(/^-?(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value), 400, "invalid_parameter");
    input = Number(value);
  } else if (schema.type === "boolean") {
    reject(value === "true" || value === "false", 400, "invalid_parameter");
    input = value === "true";
  }
  const result = compileSchema(schema).safeParse(input);
  reject(result.success, 400, "invalid_parameter");
  return result.data;
}

export function validateRequest(event: APIGatewayProxyEventV2, api: Api, route: Route, initial: PolicyContext): ValidatedRequest {
  const context = { ...initial };
  const query = parseQuery(event.rawQueryString ?? "");
  const filtered: Record<string, string> = Object.create(null);
  context.query = Object.create(null);
  for (const [key, value] of Object.entries(query)) {
    if (!route.query?.allowed.includes(key)) {
      reject(route.query?.unknown === "filter", 400, "unknown_query_parameter");
      continue;
    }
    filtered[key] = value;
    context.query[key] = typed(value, route.query.parameters?.[key]);
  }
  reject((route.query?.required ?? []).every((key) => Object.hasOwn(filtered, key)), 400, "missing_query_parameter");
  const rawQuery = Object.keys(filtered).length === Object.keys(query).length
    ? event.rawQueryString ?? "" : new URLSearchParams(filtered).toString();
  const supplied: Record<string, string> = Object.create(null);
  context.headers = Object.create(null);
  const connection = Object.entries(event.headers).find(([name]) => name.toLowerCase() === "connection")?.[1] ?? "";
  const connectionHeaders = connection.toLowerCase().split(",").map((h) => h.trim());
  for (const [rawName, value] of Object.entries(event.headers)) {
    if (value === undefined) continue;
    const name = rawName.toLowerCase();
    reject(!Object.hasOwn(supplied, name) && /^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) &&
      !/[\x00-\x1f\x7f]/.test(value), 400, "invalid_header");
    supplied[name] = value;
    if (unsafeHeaders.has(name) || connectionHeaders.includes(name) || name.startsWith("x-forwarded-") ||
      (api.authentication.type !== "bearer" && name === api.authentication.header)) continue;
    // Browser/client metadata is accepted but never forwarded.
    if (["user-agent", "accept-encoding", "x-amzn-trace-id", "x-amzn-tls-version", "x-amzn-tls-cipher-suite"].includes(name)) continue;
    if (!(route.headers?.allowed ?? ["accept", "content-type"]).includes(name)) {
      reject(route.headers?.unknown === "filter", 400, "unknown_header");
      continue;
    }
    typed(value, route.headers?.schemas?.[name]);
    context.headers[name] = value;
  }
  reject((route.headers?.required ?? []).every((h) => Object.hasOwn(context.headers, h)), 400, "missing_header");
  let body: Buffer | undefined;
  if (event.body !== undefined && event.body !== "") {
    reject(event.body.length <= Math.ceil(api.maxPayloadBytes / 3) * 4 + 4, 413, "payload_too_large");
    if (event.isBase64Encoded) reject(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(event.body), 400, "invalid_body_encoding");
    body = Buffer.from(event.body, event.isBase64Encoded ? "base64" : "utf8");
    reject(body.length <= api.maxPayloadBytes, 413, "payload_too_large");
    reject(context.method !== "GET" && context.method !== "HEAD", 400, "body_not_allowed");
    reject(route.body, 400, "body_not_allowed");
    const contentType = (context.headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    reject(!route.body.contentTypes || route.body.contentTypes.includes(contentType), 415, "unsupported_content_type");
    if (route.body.mode === "json") {
      reject(contentType === "application/json" || /^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(contentType), 415, "json_required");
      let text: string;
      try { text = new TextDecoder("utf-8", { fatal: true }).decode(body); }
      catch { reject(false, 400, "invalid_body_encoding"); }
      const parsed = parseJson(text);
      const result = compileSchema(route.body.schema!).safeParse(parsed);
      reject(result.success, 400, "invalid_payload");
      context.body = result.data;
      // Keep original JSON bytes, whitespace and content type unless a filter changed the value.
      if (!isDeepStrictEqual(JSON.parse(text), JSON.parse(JSON.stringify(result.data)))) body = Buffer.from(JSON.stringify(result.data));
    }
  }
  reject(!route.body?.required || body !== undefined, 400, "body_required");
  return { context, body, rawQuery };
}

export function applyTransform(request: ValidatedRequest, route: Route): ValidatedRequest {
  if (!route.transform) return request;
  const original = structuredClone(request.context);
  const transformed = route.transform(structuredClone(original));
  reject(transformed.api === original.api && transformed.method === original.method &&
    transformed.path === original.path && isDeepStrictEqual(transformed.params, original.params) &&
    isDeepStrictEqual(transformed.claims, original.claims), 500, "unsafe_transformation");
  const headers: Record<string, string> = Object.create(null);
  for (const [name, value] of Object.entries(transformed.headers)) {
    reject(!unsafeHeaders.has(name) && (route.headers?.allowed ?? ["accept", "content-type"]).includes(name) &&
      /^[!#$%&'*+.^_`|~0-9a-z-]+$/.test(name) && typeof value === "string" && !/[\x00-\x1f\x7f]/.test(value), 500, "unsafe_transformation");
    typed(value, route.headers?.schemas?.[name]);
    headers[name] = value;
  }
  reject((route.headers?.required ?? []).every((h) => Object.hasOwn(headers, h)), 500, "unsafe_transformation");
  const query: Record<string, string> = Object.create(null);
  const typedQuery: Record<string, unknown> = Object.create(null);
  for (const [key, value] of Object.entries(transformed.query)) {
    reject(route.query?.allowed.includes(key) && ["string", "number", "boolean"].includes(typeof value), 500, "unsafe_transformation");
    query[key] = String(value);
    typedQuery[key] = typed(String(value), route.query?.parameters?.[key]);
  }
  reject((route.query?.required ?? []).every((q) => Object.hasOwn(query, q)), 500, "unsafe_transformation");
  let body = request.body;
  if (!isDeepStrictEqual(transformed.body, original.body)) {
    reject(route.body?.mode === "json", 500, "unsafe_transformation");
    const result = compileSchema(route.body.outputSchema ?? route.body.schema!).safeParse(transformed.body);
    reject(result.success, 500, "unsafe_transformation");
    transformed.body = result.data;
    body = Buffer.from(JSON.stringify(result.data));
  }
  if (body && route.body) {
    const contentType = (headers["content-type"] ?? "").split(";")[0].trim().toLowerCase();
    reject(!route.body.contentTypes || route.body.contentTypes.includes(contentType), 500, "unsafe_transformation");
    if (route.body.mode === "json") {
      reject(contentType === "application/json" || /^application\/[a-z0-9!#$&^_.+-]+\+json$/.test(contentType), 500, "unsafe_transformation");
    }
  }
  return {
    context: { ...transformed, headers, query: typedQuery },
    rawQuery: isDeepStrictEqual(transformed.query, original.query) ? request.rawQuery : new URLSearchParams(query).toString(),
    body,
  };
}
