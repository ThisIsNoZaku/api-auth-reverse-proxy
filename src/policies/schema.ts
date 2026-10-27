import { z } from "zod";

export type Schema =
  | { type: "string"; enum?: string[]; pattern?: string; minLength?: number; maxLength?: number }
  | { type: "number" | "integer"; minimum?: number; maximum?: number }
  | { type: "boolean" | "null" }
  | { type: "array"; items: Schema; minItems?: number; maxItems?: number }
  | { type: "object"; properties: Record<string, Schema>; required?: string[]; unknown?: "reject" | "filter" };

export function compileSchema(schema: Schema): z.ZodType {
  switch (schema.type) {
    case "string": {
      let value = z.string();
      if (schema.minLength !== undefined) value = value.min(schema.minLength);
      if (schema.maxLength !== undefined) value = value.max(schema.maxLength);
      if (schema.pattern !== undefined) value = value.regex(new RegExp(schema.pattern, "u"));
      return schema.enum ? value.refine((v) => schema.enum!.includes(v)) : value;
    }
    case "number":
    case "integer": {
      let value = schema.type === "integer" ? z.number().safe() : z.number().finite();
      if (schema.minimum !== undefined) value = value.min(schema.minimum);
      if (schema.maximum !== undefined) value = value.max(schema.maximum);
      return value;
    }
    case "boolean": return z.boolean();
    case "null": return z.null();
    case "array": {
      let value = z.array(compileSchema(schema.items));
      if (schema.minItems !== undefined) value = value.min(schema.minItems);
      if (schema.maxItems !== undefined) value = value.max(schema.maxItems);
      return value;
    }
    case "object": {
      const shape = Object.fromEntries(Object.entries(schema.properties).map(([key, value]) => [
        key, schema.required?.includes(key) ? compileSchema(value) : compileSchema(value).optional(),
      ]));
      return schema.unknown === "filter" ? z.object(shape).strip() : z.object(shape).strict();
    }
  }
}

export const schemaDefinition: z.ZodType<Schema> = z.lazy(() => z.discriminatedUnion("type", [
  z.object({ type: z.literal("string"), enum: z.array(z.string()).optional(), pattern: z.string().optional(), minLength: z.number().int().nonnegative().optional(), maxLength: z.number().int().nonnegative().optional() }).strict(),
  z.object({ type: z.enum(["number", "integer"]), minimum: z.number().optional(), maximum: z.number().optional() }).strict(),
  z.object({ type: z.enum(["boolean", "null"]) }).strict(),
  z.object({ type: z.literal("array"), items: schemaDefinition, minItems: z.number().int().nonnegative().optional(), maxItems: z.number().int().nonnegative().optional() }).strict(),
  z.object({ type: z.literal("object"), properties: z.record(z.string(), schemaDefinition), required: z.array(z.string()).optional(), unknown: z.enum(["reject", "filter"]).optional() }).strict(),
]));
