import { isDeepStrictEqual } from "node:util";
import type { ProxyClaims } from "../auth/jwt.js";
import type { PolicyContext } from "../policies/engine.js";
import { fieldValue } from "../policies/engine.js";
import type { Route } from "../registry/index.js";
import { reject } from "./errors.js";

export function pathMatches(pattern: string, path: string): boolean {
  if (!pattern.startsWith("/") || pattern.includes("**") || /[%\\?#\x00-\x20]/.test(pattern)) return false;
  const regex = pattern.split("*").map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")).join("[^/]*");
  return new RegExp(`^${regex}$`, "u").test(path);
}

export function authorize(claims: ProxyClaims, route: Route, context: PolicyContext): void {
  const granted = claims.apis[context.api];
  const required = route.permissions[context.method];
  reject(Array.isArray(granted) && required?.length && required.every((p) => granted.includes(p)), 403, "permission_denied");
  const constraints = claims.constraints;
  if (!constraints) return;
  if (constraints.methods) reject(constraints.methods.includes(context.method), 403, "method_constraint");
  if (constraints.paths) reject(constraints.paths.some((p) => pathMatches(p, context.path)), 403, "path_constraint");
  if (constraints.query) {
    // A constrained query is an allow-list; omission cannot add unconstrained parameters.
    for (const [name, value] of Object.entries(context.query)) {
      reject(constraints.query[name]?.some((v: unknown) => isDeepStrictEqual(v, value)), 403, "query_constraint");
    }
  }
  if (constraints.payload) {
    for (const [selector, values] of Object.entries(constraints.payload)) {
      const actual = fieldValue(context.body, selector);
      reject(actual !== undefined && values.some((v: unknown) => isDeepStrictEqual(v, actual)), 403, "payload_constraint");
    }
  }
}
