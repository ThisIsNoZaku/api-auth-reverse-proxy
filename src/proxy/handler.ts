import type { APIGatewayProxyEventV2, APIGatewayProxyStructuredResultV2, Context } from "aws-lambda";
import { createVerifier, type ProxyClaims } from "../auth/jwt.js";
import { validateRegistry, type Registry } from "../registry/index.js";
import { resolveRoute } from "../registry/index.js";
import { evaluatePolicies, type PolicyContext } from "../policies/engine.js";
import { authorize } from "./authorization.js";
import { createCredentials, type Credentials } from "./credentials.js";
import { HttpError, reject } from "./errors.js";
import { forward, type Fetch } from "./forwarding.js";
import { parsePath } from "./parsing.js";
import { applyTransform, validateRequest } from "./validation.js";
import { configureRegistry } from "../../config/apis/extensions.js";

export interface Dependencies {
  registry: Registry;
  verify: (token: string) => Promise<ProxyClaims>;
  credentials: Credentials;
  fetcher?: Fetch;
}

export function createHandler(dependencies: Dependencies) {
  return async (event: APIGatewayProxyEventV2): Promise<APIGatewayProxyStructuredResultV2> => {
    try {
      reject(event.version === "2.0", 400, "unsupported_event");
      const auth = Object.entries(event.headers).filter(([name]) => name.toLowerCase() === "authorization");
      reject(auth.length === 1 && typeof auth[0][1] === "string", 401, "unauthorized");
      const authorization = auth[0][1]!;
      reject(authorization.length <= 16_384 &&
        authorization.startsWith("Bearer ") && /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(authorization.slice(7)), 401, "unauthorized");
      let claims: ProxyClaims;
      try { claims = await dependencies.verify(authorization.slice(7)); } catch { throw new HttpError(401, "unauthorized"); }
      const { apiId, path, encodedPath } = parsePath(event.rawPath);
      const method = event.requestContext.http.method;
      const { api, route, params } = resolveRoute(dependencies.registry, apiId, path, method);
      const context: PolicyContext = { api: apiId, method, path, params, query: {}, headers: {}, body: undefined, claims };
      const original = validateRequest(event, api, route, context);
      authorize(claims, route, original.context);
      evaluatePolicies(route.policies, original.context);
      reject(!route.validate || route.validate(structuredClone(original.context)), 403, "custom_policy_denied");
      const request = applyTransform(original, route);
      authorize(claims, route, request.context);
      evaluatePolicies(route.policies, request.context);
      reject(!route.validate || route.validate(structuredClone(request.context)), 403, "custom_policy_denied");
      reject(!request.body || request.body.length <= api.maxPayloadBytes, 413, "payload_too_large");
      return await forward(api, encodedPath, request, dependencies.credentials, dependencies.fetcher);
    } catch (error) {
      const status = error instanceof HttpError ? error.status : 500;
      const code = error instanceof HttpError ? error.code : "internal_error";
      return {
        statusCode: status,
        headers: { "content-type": "application/json", "cache-control": "no-store", ...(status === 401 ? { "www-authenticate": "Bearer" } : {}) },
        body: JSON.stringify({ error: code }),
      };
    }
  };
}

let configuredHandler: ReturnType<typeof createHandler> | undefined;
export async function handler(event: APIGatewayProxyEventV2, _context?: Context): Promise<APIGatewayProxyStructuredResultV2> {
  try {
    configuredHandler ??= createHandler({
      registry: configureRegistry(validateRegistry(JSON.parse(process.env.API_REGISTRY ?? ""))),
      verify: createVerifier({
        issuer: process.env.JWT_ISSUER ?? "local-token-issuer",
        audience: process.env.JWT_AUDIENCE ?? "multi-api-proxy",
        publicKeys: JSON.parse(process.env.JWT_PUBLIC_KEYS ?? ""),
      }),
      credentials: createCredentials(),
    });
    return await configuredHandler(event);
  } catch {
    return { statusCode: 500, headers: { "content-type": "application/json", "cache-control": "no-store" }, body: '{"error":"configuration_error"}' };
  }
}
