import type { APIGatewayProxyStructuredResultV2 } from "aws-lambda";
import type { Api } from "../registry/index.js";
import type { ValidatedRequest } from "./validation.js";
import type { Credentials } from "./credentials.js";
import { HttpError, reject } from "./errors.js";
import { processResponse } from "./response.js";

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
    return await processResponse(api, response, request.context.method);
  } catch (error) {
    if (controller.signal.aborted) throw new HttpError(504, "upstream_timeout");
    if (error instanceof HttpError) throw error;
    throw new HttpError(502, "upstream_unavailable");
  } finally {
    clearTimeout(timer);
  }
}
