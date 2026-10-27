import { GetSecretValueCommand, SecretsManagerClient } from "@aws-sdk/client-secrets-manager";
import type { Api } from "../registry/index.js";
import { reject } from "./errors.js";

type SecretResult = { SecretString?: string; SecretBinary?: Uint8Array };
export interface Credentials {
  get(api: Api): Promise<string>;
  invalidate(arn: string): void;
}

export function createCredentials(
  load: (arn: string) => Promise<SecretResult> = defaultLoad,
  ttlMs = 60_000,
  now: () => number = Date.now,
): Credentials {
  reject(Number.isFinite(ttlMs) && ttlMs > 0 && ttlMs <= 300_000, 500, "invalid_credential_cache");
  const cache = new Map<string, { expires: number; value: SecretResult }>();
  const inFlight = new Map<string, Promise<SecretResult>>();
  return {
    async get(api) {
      let entry = cache.get(api.secretArn);
      if (!entry || entry.expires <= now()) {
        cache.delete(api.secretArn);
        let pending = inFlight.get(api.secretArn);
        if (!pending) {
          pending = load(api.secretArn).then((value) => {
            cache.set(api.secretArn, { expires: now() + ttlMs, value });
            return value;
          }).finally(() => inFlight.delete(api.secretArn));
          inFlight.set(api.secretArn, pending);
        }
        entry = { expires: now() + ttlMs, value: await pending };
      }
      let value = entry.value.SecretString ??
        (entry.value.SecretBinary ? new TextDecoder("utf-8", { fatal: true }).decode(entry.value.SecretBinary) : undefined);
      const field = api.authentication.secretField;
      if (field && value) {
        const parsed: unknown = JSON.parse(value);
        value = parsed !== null && typeof parsed === "object" && Object.hasOwn(parsed, field)
          ? (parsed as Record<string, string>)[field] : undefined;
      }
      reject(typeof value === "string" && value.length > 0 && value.length <= 16_384 &&
        !/[^\x20-\x7e]/.test(value), 502, "credential_unavailable");
      return value;
    },
    invalidate(arn) { cache.delete(arn); },
  };
}

let client: SecretsManagerClient | undefined;
async function defaultLoad(arn: string): Promise<SecretResult> {
  client ??= new SecretsManagerClient({ maxAttempts: 2 });
  return client.send(new GetSecretValueCommand({ SecretId: arn }));
}
