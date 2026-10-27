import { generateKeyPair, exportJWK, exportPKCS8, importPKCS8, SignJWT, decodeJwt, decodeProtectedHeader } from 'jose';
import { createPrivateKey, randomUUID } from 'node:crypto';
import { mkdir, open, readFile, lstat, unlink, link } from 'node:fs/promises';
import { resolve, join, dirname, basename } from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { spawn } from 'node:child_process';
import { createVerifier, HTTP_METHODS, isSafePathPattern, validateClaims, type ProxyClaims } from '../auth/jwt.js';

const DEFAULT_ISSUER = 'local-token-issuer';
const DEFAULT_AUDIENCE = 'multi-api-proxy';

export const USAGE = `Usage:
  keys generate [--directory .auth-keys] [--algorithm EdDSA|RS256]
  token create --key PRIVATE.pem --kid ID --subject SUBJECT --api API --permission API:PERMISSION
    [--expires 15m] [--methods GET,POST] [--paths /path/*] [--policy JSONFILE]
    [--registry config/apis/example.json] [--issuer ISSUER] [--audience AUDIENCE]
    [--clipboard] [--output FILE]
  token inspect [TOKEN | --file FILE] [--public-keys JWKSFILE] [--issuer ISSUER] [--audience AUDIENCE]

Token creation requires --key, --kid, --subject, --api and --permission.
Repeat --api and --permission for multiple APIs and permissions.
Methods: GET, POST, PUT, PATCH, DELETE, HEAD. Path * matches within one segment; ** is unsupported.
Policy JSON contains optional methods, paths, query and payload constraints.
Token inspection reads stdin when TOKEN and --file are omitted.
`;

async function writeExclusive(path: string, value: string): Promise<void> {
  const staging = join(dirname(path), `.${basename(path)}.${randomUUID()}.pending`);
  const handle = await open(staging, 'wx', 0o600);
  try {
    try {
      await handle.writeFile(value);
      await handle.sync();
    } finally { await handle.close(); }
    // Hard-linking a complete file publishes it atomically, and fails if the destination exists.
    await link(staging, path);
  } finally { await unlink(staging); }
}

export async function generateKeys(directory = '.auth-keys', algorithm: 'EdDSA' | 'RS256' = 'EdDSA') {
  if (algorithm !== 'EdDSA' && algorithm !== 'RS256') throw new Error('Algorithm must be EdDSA or RS256');
  await mkdir(directory, { mode: 0o700, recursive: true });
  const info = await lstat(directory);
  if (!info.isDirectory() || (info.mode & 0o077) !== 0) throw new Error('Key directory must be a private directory (mode 0700)');
  const kid = randomUUID();
  const { publicKey, privateKey } = await generateKeyPair(algorithm, { extractable: true, ...(algorithm === 'RS256' ? { modulusLength: 2048 } : { crv: 'Ed25519' }) });
  const publicJwk = { ...await exportJWK(publicKey), kid, alg: algorithm, use: 'sig' };
  const privateKeyPath = join(directory, 'private.pem');
  const publicKeysPath = join(directory, 'public.jwks.json');
  const privatePem = await exportPKCS8(privateKey);
  await writeExclusive(privateKeyPath, privatePem);
  try {
    await writeExclusive(publicKeysPath, `${JSON.stringify({ keys: [publicJwk] }, null, 2)}\n`);
  } catch (error) {
    await unlink(privateKeyPath);
    throw error;
  }
  return { kid, algorithm, privateKeyPath, publicKeysPath };
}

export interface CreateTokenOptions {
  key: string;
  kid: string;
  subject: string;
  expires?: string;
  api: string[];
  permission: string[];
  methods?: string[];
  paths?: string[];
  policy?: string;
  registry?: string;
  issuer?: string;
  audience?: string;
}

export function parseDuration(value: string): number {
  const match = /^([1-9]\d*)(s|m|h)?$/u.exec(value);
  if (!match) throw new Error('Expiry must be a positive duration such as 900s or 15m');
  const seconds = Number(match[1]) * ({ s: 1, m: 60, h: 3600 }[match[2] ?? 's'] ?? 1);
  if (!Number.isSafeInteger(seconds) || seconds > 900) throw new Error('Token lifetime must not exceed 15 minutes');
  return seconds;
}

type RegistryApi = { id: string; routes: { path: string; methods: string[]; permissions: Record<string, string[]> }[] };

function parseRegistry(input: unknown): RegistryApi[] {
  if (!Array.isArray(input) || !input.length) throw new Error('Registry must be a nonempty array');
  const ids = new Set<string>();
  for (const api of input) {
    if (!api || typeof api.id !== 'string' || !api.id || ids.has(api.id) || !Array.isArray(api.routes) || !api.routes.length) throw new Error('Invalid API registry');
    ids.add(api.id);
    for (const route of api.routes) {
      if (!route || typeof route.path !== 'string' || !isSafePathPattern(route.path) ||
          !Array.isArray(route.methods) || !route.methods.length || route.methods.some((method: unknown) => typeof method !== 'string' || !HTTP_METHODS.includes(method as typeof HTTP_METHODS[number])) ||
          !route.permissions || typeof route.permissions !== 'object' || Array.isArray(route.permissions) ||
          Object.values(route.permissions).some(value => !Array.isArray(value) || value.some(permission => typeof permission !== 'string' || !permission))) throw new Error('Invalid API registry route');
    }
  }
  return input as RegistryApi[];
}

export async function createToken(options: CreateTokenOptions): Promise<string> {
  if (!options.kid || !options.subject || !options.api?.length || !options.permission?.length) throw new Error('Key identifier, subject, API and permissions are required');
  const registry = parseRegistry(JSON.parse(await readFile(options.registry ?? 'config/apis/example.json', 'utf8')));
  const selected = new Set(options.api);
  const apis: Record<string, string[]> = Object.create(null) as Record<string, string[]>;
  for (const id of selected) {
    if (!registry.some(api => api.id === id)) throw new Error('Unknown requested API');
    apis[id] = [];
  }
  for (const requested of options.permission) {
    const separator = requested.indexOf(':');
    if (separator <= 0) throw new Error('Permission must be API:permission');
    const id = requested.slice(0, separator);
    const permission = requested.slice(separator + 1);
    const api = registry.find(entry => entry.id === id);
    if (!selected.has(id) || !api || !api.routes.some(route => Object.values(route.permissions).some(values => values.includes(permission)))) throw new Error('Unknown or unselected API permission');
    if (!apis[id]!.includes(permission)) apis[id]!.push(permission);
  }
  let constraints: ProxyClaims['constraints'];
  if (options.policy) {
    const policy: unknown = JSON.parse(await readFile(options.policy, 'utf8'));
    if (!policy || typeof policy !== 'object' || Array.isArray(policy)) throw new Error('Policy must be a constraints object');
    constraints = policy as NonNullable<ProxyClaims['constraints']>;
  }
  if (options.methods || options.paths) constraints = { ...constraints, ...(options.methods ? { methods: options.methods } : {}), ...(options.paths ? { paths: options.paths } : {}) };
  if (constraints?.methods?.some(method => !registry.some(api => selected.has(api.id) &&
      api.routes.some(route => route.methods.includes(method) &&
        (route.permissions[method]?.length ?? 0) > 0 &&
        route.permissions[method]!.every(permission => apis[api.id]!.includes(permission)))))) {
    throw new Error('Method is not available with the requested permissions');
  }
  const now = Math.floor(Date.now() / 1000);
  const claims = validateClaims({
    iss: options.issuer ?? process.env.JWT_ISSUER ?? DEFAULT_ISSUER,
    aud: options.audience ?? process.env.JWT_AUDIENCE ?? DEFAULT_AUDIENCE,
    sub: options.subject,
    iat: now,
    exp: now + parseDuration(options.expires ?? '15m'),
    apis,
    ...(constraints ? { constraints } : {}),
  });
  const pem = await readFile(options.key, 'utf8');
  const nativeKey = createPrivateKey(pem);
  const algorithm = nativeKey.asymmetricKeyType === 'ed25519' ? 'EdDSA' : nativeKey.asymmetricKeyType === 'rsa' ? 'RS256' : undefined;
  if (!algorithm || (algorithm === 'RS256' && (nativeKey.asymmetricKeyDetails?.modulusLength ?? 0) < 2048)) throw new Error('Private key must be Ed25519 or RSA of at least 2048 bits');
  const privateKey = await importPKCS8(pem, algorithm);
  return new SignJWT(claims).setProtectedHeader({ alg: algorithm, typ: 'JWT', kid: options.kid }).sign(privateKey);
}

export interface InspectTokenOptions { publicKeys?: string; issuer?: string; audience?: string }
function expirationSummary(exp: unknown) {
  if (typeof exp !== 'number' || !Number.isSafeInteger(exp) || exp < 0 || exp > 8_640_000_000_000) {
    return { expiresAt: null, remainingSeconds: null, expired: null };
  }
  const remaining = exp - Math.floor(Date.now() / 1000);
  return {
    expiresAt: new Date(exp * 1000).toISOString(),
    remainingSeconds: Math.max(0, remaining),
    expired: remaining <= 0,
  };
}

export async function inspectToken(token: string, options: InspectTokenOptions = {}) {
  token = token.trim();
  const jwks = options.publicKeys ? await readFile(options.publicKeys, 'utf8') : process.env.JWT_PUBLIC_KEYS;
  if (jwks) {
    const claims = await createVerifier({
      issuer: options.issuer ?? process.env.JWT_ISSUER ?? DEFAULT_ISSUER,
      audience: options.audience ?? process.env.JWT_AUDIENCE ?? DEFAULT_AUDIENCE,
      publicKeys: JSON.parse(jwks),
    })(token);
    return { verified: true, header: decodeProtectedHeader(token), claims, ...expirationSummary(claims.exp) };
  }
  const claims = decodeJwt(token);
  return { verified: false, warning: 'UNVERIFIED: decoded data is not trusted', header: decodeProtectedHeader(token), claims, ...expirationSummary(claims.exp) };
}

async function copyToClipboard(token: string): Promise<void> {
  const command = process.platform === 'darwin' ? 'pbcopy' : process.platform === 'win32' ? 'clip.exe' : process.env.WAYLAND_DISPLAY ? 'wl-copy' : 'xclip';
  const args = command === 'xclip' ? ['-selection', 'clipboard'] : [];
  await new Promise<void>((resolvePromise, reject) => {
    const child = spawn(command, args, { stdio: ['pipe', 'ignore', 'ignore'], shell: false });
    child.on('error', () => reject(new Error('Clipboard tool unavailable')));
    child.stdin.on('error', () => reject(new Error('Clipboard write failed')));
    child.on('close', code => code === 0 ? resolvePromise() : reject(new Error('Clipboard write failed')));
    child.stdin.end(token);
  });
}

export async function main(args = process.argv.slice(2)): Promise<void> {
  if (args.includes('--help') || args[0] === 'help') {
    process.stdout.write(USAGE);
    return;
  }
  const [noun, verb, ...rest] = args;
  if (noun === 'keys' && verb === 'generate') {
    const { values } = parseArgs({ args: rest, options: { directory: { type: 'string', default: '.auth-keys' }, algorithm: { type: 'string', default: 'EdDSA' } } });
    if (values.algorithm !== 'EdDSA' && values.algorithm !== 'RS256') throw new Error('Algorithm must be EdDSA or RS256');
    console.log(JSON.stringify(await generateKeys(values.directory, values.algorithm)));
    return;
  }
  if (noun === 'token' && verb === 'create') {
    const { values } = parseArgs({ args: rest, options: {
      key: { type: 'string' }, kid: { type: 'string' }, subject: { type: 'string' }, expires: { type: 'string' },
      api: { type: 'string', multiple: true }, permission: { type: 'string', multiple: true },
      methods: { type: 'string', multiple: true }, paths: { type: 'string', multiple: true },
      policy: { type: 'string' }, registry: { type: 'string' }, issuer: { type: 'string' }, audience: { type: 'string' },
      clipboard: { type: 'boolean' }, output: { type: 'string' },
    } });
    if (!values.key || !values.kid || !values.subject) throw new Error('--key, --kid and --subject are required');
    const token = await createToken({
      ...values, key: values.key, kid: values.kid, subject: values.subject,
      api: values.api ?? [], permission: values.permission ?? [],
      ...(values.methods ? { methods: values.methods.flatMap(value => value.split(',')) } : {}),
      ...(values.paths ? { paths: values.paths.flatMap(value => value.split(',')) } : {}),
    });
    if (values.output) await writeExclusive(values.output, `${token}\n`);
    if (values.clipboard) await copyToClipboard(token);
    if (!values.output && !values.clipboard) process.stdout.write(`${token}\n`);
    return;
  }
  if (noun === 'token' && verb === 'inspect') {
    const { values, positionals } = parseArgs({ args: rest, allowPositionals: true, options: {
      file: { type: 'string' }, 'public-keys': { type: 'string' }, issuer: { type: 'string' }, audience: { type: 'string' },
    } });
    if (positionals.length > 1 || (values.file && positionals.length)) throw new Error('Provide exactly one token source');
    let token: string;
    if (values.file) token = await readFile(values.file, 'utf8');
    else if (positionals[0]) token = positionals[0];
    else {
      const chunks: Buffer[] = [];
      let size = 0;
      for await (const chunk of process.stdin) {
        const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
        size += buffer.length;
        if (size > 65536) throw new Error('Token input is too large');
        chunks.push(buffer);
      }
      token = Buffer.concat(chunks).toString('utf8');
    }
    console.log(JSON.stringify(await inspectToken(token, { publicKeys: values['public-keys'], issuer: values.issuer, audience: values.audience }), null, 2));
    return;
  }
  throw new Error('Usage: keys generate | token create | token inspect');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch(() => {
    process.stderr.write('Command failed: check arguments, policy, key files, and token validity. Run with --help for required arguments.\n');
    process.exitCode = 1;
  });
}
