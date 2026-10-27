import type { APIGatewayProxyStructuredResultV2 } from "aws-lambda";
import type { Api } from "../registry/index.js";
import { safeResponseHeaders } from "../registry/index.js";
import { reject } from "./errors.js";

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

export async function processResponse(api: Api, response: Response, method: string): Promise<APIGatewayProxyStructuredResultV2> {
  const headers: Record<string, string> = Object.create(null);
  const connectionHeaders = (response.headers.get("connection") ?? "").toLowerCase().split(",").map((h) => h.trim());
  let headerBytes = 0;
  for (const name of api.responseHeaders ?? safeResponseHeaders) {
    const value = response.headers.get(name);
    if (value !== null && !connectionHeaders.includes(name) && !/[\x00-\x1f\x7f]/.test(value)) {
      headerBytes += Buffer.byteLength(name + value);
      reject(headerBytes <= 16_384, 502, "upstream_headers_too_large");
      headers[name] = value;
    }
  }
  const empty = method === "HEAD" || [204, 205, 304].includes(response.status);
  let body: Buffer;
  if (empty) {
    await response.body?.cancel();
    body = Buffer.alloc(0);
  } else {
    body = await readLimited(response, api.maxResponseBytes);
    if (api.filterResponse) body = api.filterResponse(body, new Headers(headers));
  }
  reject(body.length <= api.maxResponseBytes, 502, "upstream_response_too_large");
  return { statusCode: response.status, headers, body: body.toString("base64"), isBase64Encoded: true };
}
