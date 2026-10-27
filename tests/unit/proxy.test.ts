import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import type { APIGatewayProxyEventV2 } from "aws-lambda";
import { validateRegistry, type Api } from "../../src/registry/index.js";
import { createHandler } from "../../src/proxy/handler.js";
import { parseJson, parsePath, parseQuery } from "../../src/proxy/parsing.js";
import { createCredentials } from "../../src/proxy/credentials.js";
import { evaluatePolicies, type PolicyContext } from "../../src/policies/engine.js";
import { pathMatches } from "../../src/proxy/authorization.js";
import type { ProxyClaims } from "../../src/auth/jwt.js";

function registry() {
  return validateRegistry(JSON.parse(readFileSync(new URL("../../config/apis/example.json", import.meta.url), "utf8")));
}
const claims: ProxyClaims = { apis: { github: ["issues:read", "issues:create"], "example-service": ["data:read"] } };
function event(path = "/github/repos/example/project/issues", method = "GET", query = "", body?: string): APIGatewayProxyEventV2 {
  return {
    version: "2.0", routeKey: "$default", rawPath: path, rawQueryString: query,
    headers: { authorization: ["Bearer", "test.jwt.signature"].join(" "), ...(body ? { "content-type": "application/json" } : {}) },
    requestContext: { http: { method } }, body, isBase64Encoded: false,
  } as unknown as APIGatewayProxyEventV2;
}
function harness(api = registry(), customClaims = claims) {
  const calls: { url: string; init?: RequestInit }[] = [];
  let credentialReads = 0;
  const handler = createHandler({
    registry: api,
    verify: async () => customClaims,
    credentials: { get: async () => { credentialReads++; return "test-only"; }, invalidate() {} },
    fetcher: async (url, init) => { calls.push({ url: String(url), init }); return new Response("success", { status: 201, headers: { "content-type": "text/plain", "set-cookie": "unsafe", "location": "https://evil.example" } }); },
  });
  return { handler, calls, credentialReads: () => credentialReads };
}

test("example registry is valid, unique and deny-by-default", () => {
  assert.equal(registry().length, 2);
  assert.throws(() => validateRegistry([registry()[0], registry()[0]]));
  const invalid = JSON.parse(JSON.stringify(registry()));
  invalid[0].baseUrl = "http://localhost/";
  assert.throws(() => validateRegistry(invalid));
  invalid[0].baseUrl = "https://api.github.com";
  invalid[0].routes[0].params = {};
  assert.throws(() => validateRegistry(invalid));
});

test("canonical paths and query strings reject ambiguity", () => {
  for (const path of ["/github/../data", "/github/%2e%2e/data", "/github/%252e%252e/data", "/github/a%2fb", "/github/a%5cb", "/github//data", "/github/a?x=1", "/github/%ff", "//evil/x", "/%67ithub/data"]) {
    assert.throws(() => parsePath(path), path);
  }
  assert.equal(parsePath("/github/repos/%65xample/project/issues").path, "/repos/example/project/issues");
  for (const query of ["page=1&page=2", "page=1&%70age=2", "x=%ff", "x=%", "x=%0d%0aevil"]) assert.throws(() => parseQuery(query));
  assert.equal(parseQuery("labels=a%2Bb+c").labels, "a+b c");
});

test("JSON rejects duplicate, escaped duplicate, prototype and imprecise keys/values", () => {
  for (const json of ['{"a":1,"a":2}', '{"a":1,"\\u0061":2}', '{"__proto__":{}}', '{"a":1,}', "[1,]", "1e999", "9007199254740993", '{"a":{"x":1,"x":2}}']) assert.throws(() => parseJson(json), json);
  assert.deepEqual(JSON.parse(JSON.stringify(parseJson('{"a":[true,null,1.5,"hello"]}'))), { a: [true, null, 1.5, "hello"] });
});

test("policy conditions support relationships, nested arrays, logical groups and deny precedence", () => {
  const context: PolicyContext = { api: "github", method: "POST", path: "/x", params: { owner: "alice" }, query: { page: 1 }, headers: {}, body: { owner: "alice", labels: ["safe"], items: [{ value: 4 }] }, claims };
  evaluatePolicies([{ effect: "allow", condition: { allOf: [
    { field: "params.owner", op: "eq", otherField: "body.owner" },
    { anyOf: [{ field: "body.labels", op: "contains", value: "safe" }, { field: "query.page", op: "gte", value: 2 }] },
    { not: { field: "body.items.0.value", op: "lt", value: 0 } },
  ] } }], context);
  assert.throws(() => evaluatePolicies([{ effect: "allow", condition: { field: "api", op: "eq", value: "github" } }, { effect: "deny", condition: { field: "method", op: "in", value: ["POST"] } }], context));
  assert.throws(() => evaluatePolicies([{ effect: "allow", condition: { field: "query.page", op: "gt", value: 99 } }], context));
  assert.equal(pathMatches("/repos/example/*", "/repos/example/project"), true);
  assert.equal(pathMatches("/repos/example/*", "/repos/example/project/issues"), false);
});

test("preserves JSON bytes, query encoding and content type while replacing credentials", async () => {
  const h = harness();
  const body = '{ "title" : "hello", "labels": ["safe"] }\n';
  const result = await h.handler(event(undefined, "POST", "labels=a%2Bb+z&page=2", body));
  assert.equal(result.statusCode, 201);
  assert.equal(h.calls[0].url, "https://api.github.com/repos/example/project/issues?labels=a%2Bb+z&page=2");
  assert.equal(Buffer.from(h.calls[0].init!.body as Uint8Array).toString(), body);
  assert.equal(new Headers(h.calls[0].init!.headers).get("authorization"), ["Bearer", "test-only"].join(" "));
  assert.equal(result.headers?.["set-cookie"], undefined);
  assert.equal(result.headers?.location, undefined);
  assert.equal(Buffer.from(result.body!, "base64").toString(), "success");
});

test("all unauthorized and invalid requests stop before secrets or upstream access", async () => {
  const cases: [APIGatewayProxyEventV2, ProxyClaims, number][] = [
    [event(), { apis: {} }, 403],
    [event("/unknown/x"), claims, 404],
    [event("/github/unknown"), claims, 404],
    [event(undefined, "DELETE"), claims, 405],
    [event("/github/repos/not!allowed/project/issues"), claims, 400],
    [event(undefined, "GET", "admin=true"), claims, 400],
    [event(undefined, "GET", "page=0"), claims, 400],
    [event(undefined, "GET", "page=1&page=2"), claims, 400],
    [event(undefined, "POST", "", '{"title":"x","extra":true}'), claims, 400],
    [event(undefined, "POST", "", '{"title":"x","title":"y"}'), claims, 400],
    [event(), { ...claims, constraints: { methods: ["POST"] } }, 403],
    [event(), { ...claims, constraints: { paths: ["/repos/other/*"] } }, 403],
    [event(undefined, "GET", "page=2"), { ...claims, constraints: { query: { page: [1] } } }, 403],
    [event(undefined, "POST", "", '{"title":"bad"}'), { ...claims, constraints: { payload: { title: ["good"] } } }, 403],
  ];
  for (const [request, permissions, status] of cases) {
    const h = harness(registry(), permissions);
    assert.equal((await h.handler(request)).statusCode, status, JSON.stringify(request));
    assert.equal(h.calls.length, 0);
    assert.equal(h.credentialReads(), 0);
  }
});

test("authentication errors, header injection and oversized bodies fail closed", async () => {
  const h = harness();
  const missing = event();
  delete missing.headers.authorization;
  assert.equal((await h.handler(missing)).statusCode, 401);
  const injection = event();
  injection.headers.accept = "ok\r\nx-header: injected";
  assert.equal((await h.handler(injection)).statusCode, 400);
  const tooBig = event(undefined, "POST", "", JSON.stringify({ title: "x".repeat(1_000_001) }));
  assert.equal((await h.handler(tooBig)).statusCode, 413);
  const extraHeader = event();
  extraHeader.headers["x-unknown"] = "denied";
  assert.equal((await h.handler(extraHeader)).statusCode, 400);
  assert.equal(h.credentialReads(), 0);
});

test("explicit query/body filtering and safe custom transformations", async () => {
  const apis = registry() as Api[];
  const route = apis[0].routes[0];
  route.query!.unknown = "filter";
  if (route.body!.schema!.type === "object") route.body!.schema!.unknown = "filter";
  let h = harness(apis);
  assert.equal((await h.handler(event(undefined, "POST", "page=1&drop=yes", '{"title":"hello","discard":1}'))).statusCode, 201);
  assert.equal(h.calls[0].url.endsWith("?page=1"), true);
  assert.equal(Buffer.from(h.calls[0].init!.body as Uint8Array).toString(), '{"title":"hello"}');
  route.transform = (ctx) => ({ ...ctx, body: { ...(ctx.body as object), title: "normalized" } });
  h = harness(apis);
  assert.equal((await h.handler(event(undefined, "POST", "", '{"title":"hello"}'))).statusCode, 201);
  assert.equal(Buffer.from(h.calls[0].init!.body as Uint8Array).toString(), '{"title":"normalized"}');
  route.transform = (ctx) => ({ ...ctx, path: "/unexpected" });
  h = harness(apis);
  assert.equal((await h.handler(event(undefined, "POST", "", '{"title":"hello"}'))).statusCode, 500);
  assert.equal(h.calls.length, 0);
});

test("transforms cannot change authentication, claim context, required headers or body content type", async () => {
  for (const transform of [
    (ctx: PolicyContext) => ({ ...ctx, claims: {} }),
    (ctx: PolicyContext) => ({ ...ctx, headers: { ...ctx.headers, authorization: "forbidden" } }),
    (ctx: PolicyContext) => ({ ...ctx, headers: { "content-type": "text/plain" } }),
    (ctx: PolicyContext) => ({ ...ctx, body: { title: "x", extra: "denied" } }),
  ]) {
    const apis = registry() as Api[];
    apis[0].routes[0].transform = transform;
    const h = harness(apis);
    assert.equal((await h.handler(event(undefined, "POST", "", '{"title":"hello"}'))).statusCode, 500);
    assert.equal(h.credentialReads(), 0);
  }
});

test("JWT constraints are enforced after transformations as well as before", async () => {
  const apis = registry() as Api[];
  apis[0].routes[0].transform = (ctx) => ({ ...ctx, body: { title: "outside-token-constraint" } });
  const h = harness(apis, { ...claims, constraints: { payload: { title: ["allowed"] } } });
  assert.equal((await h.handler(event(undefined, "POST", "", '{"title":"allowed"}'))).statusCode, 403);
  assert.equal(h.credentialReads(), 0);
});

test("credential retrieval obeys the request timeout and never forwards after expiry", async () => {
  const apis = registry() as Api[];
  apis[0].timeoutMs = 10;
  let upstreamCalls = 0;
  const handler = createHandler({
    registry: apis, verify: async () => claims,
    credentials: { get: async () => new Promise(() => {}), invalidate() {} },
    fetcher: async () => { upstreamCalls++; return new Response(); },
  });
  assert.equal((await handler(event())).statusCode, 504);
  assert.equal(upstreamCalls, 0);
});

test("invalid UTF-8 JSON, missing required body, and failing custom validators are rejected", async () => {
  const apis = registry() as Api[];
  apis[0].routes[0].body!.required = true;
  const h = harness(apis);
  assert.equal((await h.handler(event(undefined, "POST"))).statusCode, 400);
  const invalid = event(undefined, "POST", "", Buffer.from([255]).toString("base64"));
  invalid.isBase64Encoded = true;
  assert.equal((await h.handler(invalid)).statusCode, 400);
  apis[0].routes[0].validate = () => false;
  assert.equal((await h.handler(event(undefined, "POST", "", '{"title":"hello"}'))).statusCode, 403);
  assert.equal(h.credentialReads(), 0);
});

test("Secrets Manager cache expires, handles rotation, single-flights and rejects injected credentials", async () => {
  const api = registry()[0];
  let now = 0;
  let reads = 0;
  const cache = createCredentials(async () => ({ SecretString: `test-${++reads}` }), 100, () => now);
  assert.deepEqual(await Promise.all([cache.get(api), cache.get(api)]), ["test-1", "test-1"]);
  now = 101;
  assert.equal(await cache.get(api), "test-2");
  cache.invalidate(api.secretArn);
  assert.equal(await cache.get(api), "test-3");
  await assert.rejects(() => createCredentials(async () => ({ SecretString: "bad\r\ninjected" })).get(api));
  const jsonApi = registry()[1];
  assert.equal(await createCredentials(async () => ({ SecretString: '{"key":"test-value"}' })).get(jsonApi), "test-value");
  let failures = 0;
  const retry = createCredentials(async () => { if (!failures++) throw new Error("offline"); return { SecretString: "recovered" }; });
  await assert.rejects(() => retry.get(api));
  assert.equal(await retry.get(api), "recovered");
});
