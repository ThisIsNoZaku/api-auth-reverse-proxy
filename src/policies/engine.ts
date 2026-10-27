import { isDeepStrictEqual } from "node:util";
import { z } from "zod";
import { HttpError } from "../proxy/errors.js";

export type Condition =
  | { allOf: Condition[] }
  | { anyOf: Condition[] }
  | { not: Condition }
  | { field: string; op: "eq" | "in" | "matches" | "exists" | "contains" | "lt" | "lte" | "gt" | "gte"; value?: unknown; otherField?: string };

export interface PolicyContext {
  api: string;
  method: string;
  path: string;
  params: Record<string, string>;
  query: Record<string, unknown>;
  headers: Record<string, string>;
  body: unknown;
  claims: unknown;
}

export interface Policy {
  effect: "allow" | "deny";
  condition: Condition;
}

export const conditionDefinition: z.ZodType<Condition> = z.lazy(() => z.union([
  z.object({ allOf: z.array(conditionDefinition).min(1) }).strict(),
  z.object({ anyOf: z.array(conditionDefinition).min(1) }).strict(),
  z.object({ not: conditionDefinition }).strict(),
  z.object({
    field: z.string().min(1),
    op: z.enum(["eq", "in", "matches", "exists", "contains", "lt", "lte", "gt", "gte"]),
    value: z.unknown().optional(),
    otherField: z.string().optional(),
  }).strict(),
]));

export function fieldValue(context: unknown, selector: string): unknown {
  let value = context;
  for (const key of selector.split(".")) {
    if (key === "__proto__" || key === "constructor" || key === "prototype" ||
        value === null || typeof value !== "object" || !Object.hasOwn(value, key)) return undefined;
    value = (value as Record<string, unknown>)[key];
  }
  return value;
}

export function matches(condition: Condition, context: PolicyContext): boolean {
  if ("allOf" in condition) return condition.allOf.every((c) => matches(c, context));
  if ("anyOf" in condition) return condition.anyOf.some((c) => matches(c, context));
  if ("not" in condition) return !matches(condition.not, context);
  const actual = fieldValue(context, condition.field);
  const expected = condition.otherField ? fieldValue(context, condition.otherField) : condition.value;
  switch (condition.op) {
    case "exists": return (actual !== undefined) === (expected ?? true);
    case "eq": return actual !== undefined && expected !== undefined && isDeepStrictEqual(actual, expected);
    case "in": return Array.isArray(expected) && expected.some((v) => isDeepStrictEqual(actual, v));
    case "contains": return Array.isArray(actual) && actual.some((v) => isDeepStrictEqual(v, expected));
    case "matches": return typeof actual === "string" && typeof expected === "string" && new RegExp(expected, "u").test(actual);
    case "lt": return typeof actual === "number" && typeof expected === "number" && actual < expected;
    case "lte": return typeof actual === "number" && typeof expected === "number" && actual <= expected;
    case "gt": return typeof actual === "number" && typeof expected === "number" && actual > expected;
    case "gte": return typeof actual === "number" && typeof expected === "number" && actual >= expected;
  }
}

export function evaluatePolicies(policies: Policy[] | undefined, context: PolicyContext): void {
  if (!policies?.length) return; // The resolved registry route is the base allow rule.
  if (policies.some((p) => p.effect === "deny" && matches(p.condition, context))) throw new HttpError(403, "policy_denied");
  const allows = policies.filter((p) => p.effect === "allow");
  if (allows.length && !allows.some((p) => matches(p.condition, context))) throw new HttpError(403, "policy_denied");
}
