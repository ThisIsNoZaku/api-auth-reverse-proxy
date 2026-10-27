import { readFileSync } from 'node:fs';
import { createPublicKey, type JsonWebKey } from 'node:crypto';
import { createVerifier, type JwtConfig } from '../../src/auth/jwt.js';
import { validateRegistry } from '../../src/registry/index.js';

export interface DeploymentConfig {
  registry: Record<string, unknown>[];
  publicKeys: { keys: Record<string, unknown>[] };
  region: string;
  environment: string;
  issuer: string;
  audience: string;
  memorySize: number;
  timeoutSeconds: number;
  reservedConcurrency: number;
  rateLimit: number;
  burstLimit: number;
  logRetentionDays: number;
  durationAlarmThresholdMs: number;
  kmsKeyArns: string[];
}

export const defaults = {
  region: 'us-east-1',
  environment: 'dev',
  issuer: 'local-token-issuer',
  audience: 'multi-api-proxy',
  memorySize: 256,
  timeoutSeconds: 30,
  reservedConcurrency: 10,
  rateLimit: 20,
  burstLimit: 10,
  logRetentionDays: 30,
};

const secretArnPattern = /^arn:aws(?:-us-gov|-cn)?:secretsmanager:[a-z0-9-]+:\d{12}:secret:[A-Za-z0-9/_+=.@-]+$/;
const keyArnPattern = /^arn:aws(?:-us-gov|-cn)?:kms:[a-z0-9-]+:\d{12}:key\/[A-Za-z0-9-]+$/;
const retentionDays = [1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653];

export function parseConfig(input: unknown): DeploymentConfig {
  if (!input || typeof input !== 'object' || Array.isArray(input)) {
    throw new Error('Deployment configuration must be a JSON object');
  }
  const raw = input as Record<string, unknown>;
  const config = {
    ...defaults,
    ...raw,
    kmsKeyArns: raw.kmsKeyArns ?? [],
    durationAlarmThresholdMs: raw.durationAlarmThresholdMs ?? Number(raw.timeoutSeconds ?? defaults.timeoutSeconds) * 800,
  } as DeploymentConfig;
  if (!Array.isArray(config.registry) || config.registry.length === 0) {
    throw new Error('registry must be a nonempty JSON array');
  }
  for (const entry of config.registry) {
    if (!entry || typeof entry !== 'object' || typeof entry.secretArn !== 'string' || !secretArnPattern.test(entry.secretArn)) {
      throw new Error('Every registry entry must have an exact Secrets Manager secretArn (wildcards are forbidden)');
    }
  }
  try {
    validateRegistry(config.registry);
  } catch {
    throw new Error('registry must be a complete, valid public API registry with HTTPS upstreams and no embedded credentials');
  }
  if (!config.publicKeys || !Array.isArray(config.publicKeys.keys) || config.publicKeys.keys.length === 0) {
    throw new Error('publicKeys must be a nonempty public JWKS');
  }
  for (const key of config.publicKeys.keys) {
    if (!key || !['RSA', 'OKP'].includes(String(key.kty)) ||
        ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some((field) => field in key)) {
      throw new Error('publicKeys must contain only asymmetric public keys, never private or symmetric key material');
    }
  }
  if (!Array.isArray(config.kmsKeyArns) || !config.kmsKeyArns.every((arn) => typeof arn === 'string' && keyArnPattern.test(arn))) {
    throw new Error('kmsKeyArns must contain exact KMS key ARNs');
  }
  if (!/^[a-z][a-z0-9-]{0,29}$/.test(config.environment)) {
    throw new Error('environment must be a lowercase name, at most 30 characters');
  }
  if (!/^[a-z0-9-]+$/.test(config.region)) throw new Error('region is invalid');
  for (const key of ['issuer', 'audience'] as const) {
    if (typeof config[key] !== 'string' || config[key].length === 0) throw new Error(`${key} must be a nonempty string`);
  }
  try {
    createVerifier({
      issuer: config.issuer, audience: config.audience,
      publicKeys: config.publicKeys as JwtConfig['publicKeys'],
    });
    for (const key of config.publicKeys.keys) createPublicKey({ key: key as JsonWebKey, format: 'jwk' });
  } catch {
    throw new Error('publicKeys must contain valid, uniquely identified Ed25519 or RSA-2048+ public verification keys');
  }
  for (const [key, min, max] of [
    ['memorySize', 128, 10240], ['timeoutSeconds', 1, 30], ['reservedConcurrency', 1, 1000],
    ['rateLimit', 1, 100000], ['burstLimit', 1, 100000], ['durationAlarmThresholdMs', 1, 30000],
  ] as const) {
    if (!Number.isInteger(config[key]) || config[key] < min || config[key] > max) {
      throw new Error(`${key} must be an integer between ${min} and ${max}`);
    }
  }
  if (!retentionDays.includes(config.logRetentionDays)) throw new Error('logRetentionDays is not a supported CloudWatch retention period');
  const environment = {
    API_REGISTRY: JSON.stringify(config.registry),
    JWT_PUBLIC_KEYS: JSON.stringify(config.publicKeys),
    JWT_ISSUER: config.issuer,
    JWT_AUDIENCE: config.audience,
  };
  const environmentBytes = Object.entries(environment)
    .reduce((size, [key, value]) => size + Buffer.byteLength(key) + Buffer.byteLength(value), 0);
  if (environmentBytes > 4096) throw new Error(`Lambda environment exceeds the 4096-byte limit (${environmentBytes} bytes)`);
  return config;
}

export function loadConfig(path: string): DeploymentConfig {
  return parseConfig(JSON.parse(readFileSync(path, 'utf8')));
}
