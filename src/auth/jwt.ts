import { importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import { z } from 'zod';

export interface ProxyClaims extends JWTPayload {
  apis: Record<string, string[]>;
  constraints?: {
    methods?: string[];
    paths?: string[];
    query?: Record<string, unknown[]>;
    payload?: Record<string, unknown[]>;
  };
}

export type JwtConfig = {
  issuer: string;
  audience: string;
  publicKeys: { keys: JWK[] };
  maxTokenLifetimeSeconds?: number;
};

const identifier = z.string().min(1).max(256).refine(value => !/[\s\x00-\x1f\x7f]/u.test(value));
export const HTTP_METHODS = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD'] as const;

/** A star matches within one pathname segment; recursive globs are not supported. */
export function isSafePathPattern(path: string): boolean {
  return path.length > 0 && path.length <= 2048 && path.startsWith('/') &&
    !/[\s\x00-\x1f\x7f\\%?#{}\[\]]/u.test(path) && !path.includes('//') && !path.includes('**') &&
    path.split('/').every(segment =>
      segment !== '.' && segment !== '..');
}

const valueLists = z.record(z.string().min(1).max(256), z.array(z.json()).min(1).max(100));
const constraintsSchema = z.strictObject({
  methods: z.array(z.enum(HTTP_METHODS)).min(1).max(HTTP_METHODS.length).optional(),
  paths: z.array(z.string().refine(isSafePathPattern, 'Unsafe path pattern')).min(1).max(100).optional(),
  query: valueLists.optional(),
  payload: valueLists.optional(),
});
const claimsSchema = z.strictObject({
  iss: z.string().min(1),
  aud: z.union([z.string().min(1), z.array(z.string().min(1)).min(1)]),
  sub: z.string().min(1).max(1024),
  iat: z.number().int().nonnegative().safe(),
  exp: z.number().int().nonnegative().safe(),
  nbf: z.number().int().nonnegative().safe().optional(),
  jti: z.string().min(1).optional(),
  apis: z.record(identifier, z.array(identifier).min(1).max(100)).refine(value => Object.keys(value).length > 0),
  constraints: constraintsSchema.optional(),
});

export function validateClaims(payload: unknown, maxTokenLifetimeSeconds = 900, now = Math.floor(Date.now() / 1000)): ProxyClaims {
  const claims = claimsSchema.parse(payload);
  if (!Number.isSafeInteger(maxTokenLifetimeSeconds) || maxTokenLifetimeSeconds <= 0 ||
      claims.iat > now || claims.exp <= now || claims.exp <= claims.iat ||
      claims.exp - claims.iat > maxTokenLifetimeSeconds ||
      (claims.nbf !== undefined && (claims.nbf > now || claims.nbf >= claims.exp))) {
    throw new Error('Invalid token validity period');
  }
  return claims;
}

function keyAlgorithm(key: JWK): 'EdDSA' | 'RS256' {
  if (['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k'].some(field => field in key)) {
    throw new Error('Only public verification keys are permitted');
  }
  if (!key.kid || typeof key.kid !== 'string' || (key.use !== undefined && key.use !== 'sig') ||
      (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || key.key_ops.length !== 1 || key.key_ops[0] !== 'verify'))) {
    throw new Error('Invalid verification key metadata');
  }
  if (key.kty === 'OKP' && key.crv === 'Ed25519' && typeof key.x === 'string' &&
      (key.alg === undefined || key.alg === 'EdDSA') && Buffer.from(key.x, 'base64url').length === 32) return 'EdDSA';
  if (key.kty === 'RSA' && typeof key.n === 'string' && typeof key.e === 'string' &&
      (key.alg === undefined || key.alg === 'RS256')) {
    const modulus = Buffer.from(key.n, 'base64url');
    let first = 0;
    while (first < modulus.length && modulus[first] === 0) first++;
    const leading = modulus[first];
    const bits = leading === undefined ? 0 : (modulus.length - first - 1) * 8 + Math.floor(Math.log2(leading)) + 1;
    if (bits >= 2048) return 'RS256';
  }
  throw new Error('Unsupported or weak verification key');
}

export function createVerifier(config: JwtConfig): (token: string) => Promise<ProxyClaims> {
  const lifetime = config.maxTokenLifetimeSeconds ?? 900;
  if (!config.issuer || !config.audience || !Number.isSafeInteger(lifetime) || lifetime <= 0 ||
      !Array.isArray(config.publicKeys?.keys) || config.publicKeys.keys.length === 0) {
    throw new Error('Invalid JWT verification configuration');
  }
  const { issuer, audience } = config;
  const keys = new Map<string, { algorithm: 'EdDSA' | 'RS256'; jwk: JWK }>();
  for (const original of config.publicKeys.keys) {
    const key = structuredClone(original);
    const algorithm = keyAlgorithm(key);
    if (keys.has(key.kid!)) throw new Error('Duplicate verification key identifier');
    keys.set(key.kid!, { algorithm, jwk: key });
  }
  return async token => {
    if (typeof token !== 'string' || token.length > 65536) throw new Error('Invalid token');
    const { payload } = await jwtVerify(token, async header => {
      if (typeof header.kid !== 'string' || header.jwk !== undefined || header.jku !== undefined || header.x5u !== undefined) {
        throw new Error('Untrusted token key');
      }
      const entry = keys.get(header.kid);
      if (!entry || header.alg !== entry.algorithm) throw new Error('Untrusted token key or algorithm');
      return importJWK(entry.jwk, entry.algorithm);
    }, {
      algorithms: ['EdDSA', 'RS256'],
      issuer,
      audience,
      requiredClaims: ['iss', 'aud', 'sub', 'iat', 'exp', 'apis'],
      clockTolerance: 0,
    });
    return validateClaims(payload, lifetime);
  };
}
