import type { APIGatewayProxyStructuredResultV2 } from "aws-lambda";
import type { Api } from "../registry/index.js";
import { safeResponseHeaders } from "../registry/index.js";
import type { ValidatedRequest } from "./validation.js";
import type { Credentials } from "./credentials.js";
import { HttpError, reject } from "./errors.js";

export type Fetch = typeof globalThis.fetch;

async function abortable<T>(operation: Promise<T>, signal: AbortSignal): Promise<T> {
  signal.throwIfAborted();
  let onAbort: () => void = () => undefined;
  const aborted = new Promise<never>((_, rejectPromise) => {
    onAbort = () => rejectPromise(signal.reason);
    signal.addEventListener("abort", onAbort, { once: true });
  });
  try { return await Promise.race([operation, aborted]); }
  finally { signal.removeEventListener("abort", onAbort); }
}

export function upstreamUrl(api: Api, encodedPath: string, rawQuery: string): URL {
  const base = new URL(api.baseUrl);
  const prefix = base.pathname.replace(/\/$/, "");
  const target = new URL(base.origin + prefix + encodedPath + (rawQuery ? `?${rawQuery}` : ""));
  reject(base.protocol === "https:" && target.origin === base.origin &&
    target.pathname.startsWith(prefix + "/") && !target.username && !target.password && !target.hash, 400, "invalid_upstream_path");
  return target;
}

async function readLimited(response: Response, maxBytes: number): Promise<Buffer> {
  if (!response.body) return Buffer.alloc(0);
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let length = 0;
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) return Buffer.concat(chunks, length);
      length += value.byteLength;
      reject(length <= maxBytes, 502, "upstream_response_too_large");
      chunks.push(Buffer.from(value));
    }
  } finally {
    await reader.cancel().catch(() => undefined);
    reader.releaseLock();
  }
}

export async function forward(
  api: Api,
  encodedPath: string,
  request: ValidatedRequest,
  credentials: Credentials,
  fetcher: Fetch = fetch,
): Promise<APIGatewayProxyStructuredResultV2> {
  const url = upstreamUrl(api, encodedPath, request.rawQuery);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), api.timeoutMs);
  try {
    const secret = await abortable(credentials.get(api), controller.signal);
    reject(!controller.signal.aborted, 504, "upstream_timeout");
    const headers = new Headers(request.context.headers);
    if (api.authentication.type === "bearer") headers.set("authorization", ["Bearer", secret].join(" "));
    else headers.set(api.authentication.header, (api.authentication.prefix ?? "") + secret);
    const response = await fetcher(url, {
      method: request.context.method,
      headers,
      body: request.body ? new Uint8Array(request.body) : undefined,
      redirect: "manual",
      signal: controller.signal,
    });
    if (response.status === 401 || response.status === 403) credentials.invalidate(api.secretArn);
    const responseHeaders: Record<string, string> = Object.create(null);
    const connectionHeaders = (response.headers.get("connection") ?? "").toLowerCase().split(",").map((h) => h.trim());
    let headerBytes = 0;
    for (const name of api.responseHeaders ?? safeResponseHeaders) {
      const value = response.headers.get(name);
      if (value !== null && !connectionHeaders.includes(name) && !/[\x00-\x1f\x7f]/.test(value)) {
        headerBytes += Buffer.byteLength(name + value);
        reject(headerBytes <= 16_384, 502, "upstream_headers_too_large");
        responseHeaders[name] = value;
      }
    }
    let body = request.context.method === "HEAD" ? Buffer.alloc(0) : await readLimited(response, api.maxResponseBytes);
    if (request.context.method === "HEAD") await response.body?.cancel();
    if (api.filterResponse) body = api.filterResponse(body, new Headers(responseHeaders));
    reject(body.length <= api.maxResponseBytes, 502, "upstream_response_too_large");
    return {
      statusCode: response.status,
      headers: responseHeaders,
      body: body.toString("base64"),
      isBase64Encoded: true,
    };
  } catch (error) {
    if (controller.signal.aborted) throw new HttpError(504, "upstream_timeout");
    if (error instanceof HttpError) throw error;
    throw new HttpError(502, "upstream_unavailable");
  } finally {
    clearTimeout(timer);
  }
}
