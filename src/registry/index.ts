import { z } from "zod";
import { schemaDefinition, compileSchema, type Schema } from "../policies/schema.js";
import { conditionDefinition, type Policy, type PolicyContext } from "../policies/engine.js";
import { reject } from "../proxy/errors.js";

export const methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"] as const;
export type Method = typeof methods[number];
const methodDefinition = z.enum(methods);
const headerName = z.string().regex(/^[!#$%&'*+.^_`|~0-9a-z-]+$/);
const safeName = z.string().regex(/^[A-Za-z][A-Za-z0-9_-]*$/);

export const unsafeHeaders = new Set([
  "authorization", "proxy-authorization", "x-api-key", "cookie", "set-cookie",
  "host", "connection", "keep-alive", "proxy-authenticate", "te", "trailer",
  "transfer-encoding", "upgrade", "content-length", "forwarded", "via",
  "x-forwarded-for", "x-forwarded-host", "x-forwarded-proto",
]);
export const safeResponseHeaders = ["content-type", "cache-control", "etag", "last-modified", "retry-after", "x-ratelimit-limit", "x-ratelimit-remaining", "x-ratelimit-reset"];

const queryDefinition = z.object({
  allowed: z.array(z.string().min(1)),
  unknown: z.enum(["reject", "filter"]).default("reject"),
  required: z.array(z.string()).optional(),
  parameters: z.record(z.string(), schemaDefinition).optional(),
}).strict();

const routeDefinition = z.object({
  path: z.string().regex(/^\/(?:[A-Za-z0-9._~!$&'()+,;=@-]+|:[A-Za-z][A-Za-z0-9_]*)(?:\/(?:[A-Za-z0-9._~!$&'()+,;=@-]+|:[A-Za-z][A-Za-z0-9_]*))*$|^\/$/),
  methods: z.array(methodDefinition).min(1),
  permissions: z.record(z.string(), z.array(z.string().min(1)).min(1)),
  params: z.record(z.string(), schemaDefinition).optional(),
  query: queryDefinition.optional(),
  headers: z.object({ allowed: z.array(headerName), unknown: z.enum(["reject", "filter"]).default("reject"), required: z.array(headerName).optional(), schemas: z.record(headerName, schemaDefinition).optional() }).strict().optional(),
  body: z.object({ mode: z.enum(["json", "binary"]), schema: schemaDefinition.optional(), outputSchema: schemaDefinition.optional(), required: z.boolean().optional(), contentTypes: z.array(z.string()).min(1).optional() }).strict().optional(),
  policies: z.array(z.object({ effect: z.enum(["allow", "deny"]), condition: conditionDefinition }).strict()).optional(),
}).strict();

const apiDefinition = z.object({
  id: safeName,
  baseUrl: z.string().url(),
  secretArn: z.string().regex(/^arn:aws(?:-[a-z]+)?:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+$/),
  authentication: z.discriminatedUnion("type", [
    z.object({ type: z.literal("bearer"), secretField: z.string().optional() }).strict(),
    z.object({ type: z.enum(["apiKey", "custom"]), header: headerName, prefix: z.string().optional(), secretField: z.string().optional() }).strict(),
  ]),
  routes: z.array(routeDefinition).min(1),
  maxPayloadBytes: z.number().int().positive().max(4_000_000).default(1_000_000),
  maxResponseBytes: z.number().int().positive().max(4_000_000).default(4_000_000),
  timeoutMs: z.number().int().positive().max(25_000).default(10_000),
  responseHeaders: z.array(headerName).optional(),
}).strict();

export type Route = z.infer<typeof routeDefinition> & {
  validate?: (context: PolicyContext) => boolean;
  transform?: (context: PolicyContext) => PolicyContext;
};
export type Api = Omit<z.infer<typeof apiDefinition>, "routes"> & {
  routes: Route[];
  filterResponse?: (body: Buffer, headers: Headers) => Buffer;
};
export type Registry = readonly Api[];

function validateSchema(schema: Schema): void {
  compileSchema(schema);
  if (schema.type === "object") {
    reject((schema.required ?? []).every((key) => Object.hasOwn(schema.properties, key)), 500, "invalid_registry");
    Object.values(schema.properties).forEach(validateSchema);
  }
  if (schema.type === "array") validateSchema(schema.items);
}

export function validateRegistry(input: unknown): Registry {
  const apis = z.array(apiDefinition).min(1).parse(input);
  const ids = new Set<string>();
  for (const api of apis) {
    reject(!ids.has(api.id), 500, "invalid_registry");
    ids.add(api.id);
    const url = new URL(api.baseUrl);
    reject(url.protocol === "https:" && !url.username && !url.password && !url.search && !url.hash &&
      !/%|\\/.test(api.baseUrl) && !url.hostname.endsWith(".") && url.pathname.split("/").every((s) => s !== "." && s !== ".."), 500, "invalid_registry");
    if (api.authentication.type !== "bearer") {
      reject(!unsafeHeaders.has(api.authentication.header) || api.authentication.header === "x-api-key" || api.authentication.header === "authorization", 500, "invalid_registry");
      reject(!/[\r\n\x00]/.test(api.authentication.prefix ?? ""), 500, "invalid_registry");
    }
    const routes = new Set<string>();
    for (const route of api.routes) {
      const segments = route.path.split("/");
      const paramNames = segments.filter((s) => s.startsWith(":")).map((s) => s.slice(1));
      const canonical = segments.map((s) => s.startsWith(":") ? ":" : s).join("/");
      reject(!routes.has(canonical) && new Set(paramNames).size === paramNames.length && segments.every((s) => s !== "." && s !== ".."), 500, "invalid_registry");
      routes.add(canonical);
      reject(route.methods.every((m) => (route.permissions[m]?.length ?? 0) > 0) &&
        Object.keys(route.permissions).every((m) => route.methods.includes(m as Method)), 500, "invalid_registry");
      reject(paramNames.every((p) => route.params?.[p] !== undefined) &&
        Object.keys(route.params ?? {}).every((p) => paramNames.includes(p)), 500, "invalid_registry");
      const credentialHeader = api.authentication.type === "bearer" ? "authorization" : api.authentication.header;
      reject((route.headers?.allowed ?? []).every((h) => !unsafeHeaders.has(h) && h !== credentialHeader), 500, "invalid_registry");
      reject((route.headers?.required ?? []).every((h) => route.headers?.allowed.includes(h)) &&
        Object.keys(route.headers?.schemas ?? {}).every((h) => route.headers?.allowed.includes(h)), 500, "invalid_registry");
      reject((route.query?.required ?? []).every((q) => route.query?.allowed.includes(q)) &&
        Object.keys(route.query?.parameters ?? {}).every((q) => route.query?.allowed.includes(q)), 500, "invalid_registry");
      reject(!route.body || route.body.mode !== "json" || !!route.body.schema, 500, "invalid_registry");
      for (const schema of [...Object.values(route.params ?? {}), ...Object.values(route.query?.parameters ?? {}), ...Object.values(route.headers?.schemas ?? {}), route.body?.schema, route.body?.outputSchema]) {
        if (schema) validateSchema(schema);
      }
    }
    reject((api.responseHeaders ?? []).every((h) => safeResponseHeaders.includes(h)), 500, "invalid_registry");
  }
  return apis;
}

export function resolveRoute(registry: Registry, apiId: string, path: string, method: string): { api: Api; route: Route; params: Record<string, string> } {
  const api = registry.find((entry) => entry.id === apiId);
  reject(api, 404, "unknown_api");
  const candidates = api.routes.flatMap((route) => {
    const pattern = route.path.split("/");
    const segments = path.split("/");
    if (pattern.length !== segments.length) return [];
    const params: Record<string, string> = Object.create(null);
    for (let i = 0; i < pattern.length; i++) {
      if (pattern[i].startsWith(":")) params[pattern[i].slice(1)] = segments[i];
      else if (pattern[i] !== segments[i]) return [];
    }
    return [{ route, params, specificity: pattern.filter((p) => !p.startsWith(":")).length }];
  }).sort((a, b) => b.specificity - a.specificity);
  reject(candidates.length, 404, "unknown_route");
  const selected = candidates[0];
  reject(!candidates[1] || selected.specificity !== candidates[1].specificity, 500, "ambiguous_registry");
  reject(selected.route.methods.includes(method as Method), 405, "method_not_allowed");
  for (const [name, value] of Object.entries(selected.params)) {
    reject(compileSchema(selected.route.params![name]).safeParse(value).success, 400, "invalid_path_parameter");
  }
  return { api, route: selected.route, params: selected.params };
}
