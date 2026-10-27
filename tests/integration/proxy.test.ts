import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer, type IncomingMessage } from "node:http";
import { once } from "node:events";
import { generateKeyPair, exportJWK, SignJWT } from "jose";
import type { AddressInfo } from "node:net";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { createHandler } from "../../src/proxy/handler.js";
import { validateRegistry } from "../../src/registry/index.js";
import type { Fetch } from "../../src/proxy/forwarding.js";
import { createVerifier } from "../../src/auth/jwt.js";

test("signed short-lived JWTs authorize only the selected API before retrieving any credential", async () => {
  const { publicKey, privateKey } = await generateKeyPair("EdDSA", { extractable: true });
  const registry = validateRegistry(["first", "second"].map((id) => ({
    id, baseUrl: "https://registered.example",
    secretArn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:${id}-test`,
    authentication: { type: "bearer" },
    routes: [{ path: "/status", methods: ["GET"], permissions: { GET: ["status:read"] } }],
  })));
  let credentialReads = 0;
  let requests = 0;
  const handler = createHandler({
    registry,
    verify: createVerifier({
      issuer: "local-token-issuer", audience: "multi-api-proxy",
      publicKeys: { keys: [{ ...await exportJWK(publicKey), kid: "integration-key", alg: "EdDSA" }] },
    }),
    credentials: { get: async () => { credentialReads++; return "test-only"; }, invalidate() {} },
    fetcher: async () => { requests++; return new Response("ok"); },
  });
  const token = await new SignJWT({ apis: { first: ["status:read"] } })
    .setProtectedHeader({ alg: "EdDSA", kid: "integration-key" })
    .setSubject("integration-agent").setIssuer("local-token-issuer").setAudience("multi-api-proxy")
    .setIssuedAt().setExpirationTime("15m").sign(privateKey);
  const request = (id: string, value = token) => ({
    version: "2.0", routeKey: "$default", rawPath: `/${id}/status`, rawQueryString: "",
    headers: { authorization: ["Bearer", value].join(" ") }, requestContext: { http: { method: "GET" } },
  }) as unknown as APIGatewayProxyEventV2;
  assert.equal((await handler(request("first"))).statusCode, 200);
  assert.equal((await handler(request("second"))).statusCode, 403);
  const parts = token.split(".");
  parts[1] = Buffer.from(JSON.stringify({ apis: { second: ["status:read"] } })).toString("base64url");
  assert.equal((await handler(request("second", parts.join(".")))).statusCode, 401);
  assert.equal(credentialReads, 1);
  assert.equal(requests, 1);
});

test("mock HTTP upstream: all methods, API credentials, binary data, redirects, failures and timeouts", async (t) => {
  const received: { method?: string; url?: string; headers: IncomingMessage["headers"]; body: Buffer }[] = [];
  const server = createServer(async (req, res) => {
    const chunks: Buffer[] = [];
    for await (const chunk of req) chunks.push(Buffer.from(chunk));
    received.push({ method: req.method, url: req.url, headers: req.headers, body: Buffer.concat(chunks) });
    if (req.url === "/v1/redirect") { res.writeHead(302, { location: "http://localhost/credential-theft" }); res.end(); return; }
    if (req.url === "/v1/fail") { res.writeHead(503, { "retry-after": "5" }); res.end("unavailable"); return; }
    if (req.url === "/v1/slow") { setTimeout(() => res.end("late"), 150).unref(); return; }
    if (req.url === "/v1/large") { res.end(Buffer.alloc(1025)); return; }
    res.writeHead(200, { "content-type": "application/octet-stream", "set-cookie": "never-forward", "connection": "close" });
    res.end(Buffer.concat(chunks));
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  t.after(() => { server.closeAllConnections(); server.close(); });
  const port = (server.address() as AddressInfo).port;
  // Only this test transport maps a fixed trusted HTTPS origin to the local HTTP mock.
  const transport: Fetch = (url, init) => {
    const target = new URL(String(url));
    assert.equal(target.origin, "https://registered.example");
    return fetch(`http://127.0.0.1:${port}${target.pathname}${target.search}`, init);
  };
  const registry = validateRegistry(["first", "second"].map((id) => ({
    id, baseUrl: "https://registered.example/v1",
    secretArn: `arn:aws:secretsmanager:us-east-1:123456789012:secret:${id}-test`,
    authentication: id === "first" ? { type: "bearer" } : { type: "custom", header: "x-service-key", prefix: "Key " },
    maxResponseBytes: 1024, timeoutMs: 1000,
    routes: [{
      path: "/:action", methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"],
      permissions: Object.fromEntries(["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"].map((m) => [m, ["access"]])),
      params: { action: { type: "string", pattern: "^[a-z]+$" } },
      query: { allowed: ["q"], unknown: "reject" },
      headers: { allowed: ["content-type", "accept"], unknown: "reject" },
      body: { mode: "binary", contentTypes: ["application/octet-stream"] },
    }],
  })));
  const handler = createHandler({
    registry,
    verify: async () => ({ apis: { first: ["access"], second: ["access"] } }),
    credentials: { get: async (api) => `test-${api.id}`, invalidate() {} },
    fetcher: transport,
  });
  const request = (method: string, action = "echo", id = "first", body?: Buffer) => ({
    version: "2.0", routeKey: "$default", rawPath: `/${id}/${action}`, rawQueryString: action === "echo" ? "q=hello%20world" : "",
    headers: { authorization: ["Bearer", "test.jwt.signature"].join(" "), "content-type": "application/octet-stream", cookie: "caller-secret", "x-api-key": "caller-secret" },
    body: body?.toString("base64"), isBase64Encoded: true, requestContext: { http: { method } },
  }) as unknown as APIGatewayProxyEventV2;
  const bytes = Buffer.from([0, 255, 254, 128, 10, 13]);
  for (const method of ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"]) {
    const body = ["GET", "HEAD"].includes(method) ? undefined : bytes;
    const result = await handler(request(method, "echo", "first", body));
    assert.equal(result.statusCode, 200);
    assert.deepEqual(Buffer.from(result.body!, "base64"), body ?? Buffer.alloc(0));
    const upstream = received.at(-1)!;
    assert.equal(upstream.method, method);
    assert.equal(upstream.url, "/v1/echo?q=hello%20world");
    assert.equal(upstream.headers.authorization, ["Bearer", "test-first"].join(" "));
    assert.equal(upstream.headers.cookie, undefined);
    assert.equal(upstream.headers["x-api-key"], undefined);
    assert.equal(result.headers?.["set-cookie"], undefined);
  }
  assert.equal((await handler(request("GET", "echo", "second"))).statusCode, 200);
  assert.equal(received.at(-1)!.headers.authorization, undefined);
  assert.equal(received.at(-1)!.headers["x-service-key"], "Key test-second");
  const before = received.length;
  const redirect = await handler(request("GET", "redirect"));
  assert.equal(redirect.statusCode, 302);
  assert.equal(received.length, before + 1);
  assert.equal(redirect.headers?.location, undefined);
  const failure = await handler(request("GET", "fail"));
  assert.equal(failure.statusCode, 503);
  assert.equal(failure.headers?.["retry-after"], "5");
  assert.equal((await handler(request("GET", "large"))).statusCode, 502);
  (registry[0] as { timeoutMs: number }).timeoutMs = 20;
  assert.equal((await handler(request("GET", "slow"))).statusCode, 504);
  assert.equal((await handler(request("GET", "echo", "notregistered"))).statusCode, 404);
  assert.equal((await handler(request("GET", "%2e%2e"))).statusCode, 400);
});
