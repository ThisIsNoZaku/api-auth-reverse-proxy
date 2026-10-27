import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdir, readFile, readdir, rm, stat, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { exportJWK, generateKeyPair, SignJWT, type JWK } from 'jose';
import { createVerifier, HTTP_METHODS, isSafePathPattern, type ProxyClaims } from '../../src/auth/jwt.js';
import { createToken, generateKeys, inspectToken, parseDuration, USAGE } from '../../src/cli/index.js';
import { authorize, pathMatches } from '../../src/proxy/authorization.js';

const issuer = 'test-issuer';
const audience = 'test-audience';
const now = () => Math.floor(Date.now() / 1000);
const ed = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
const jwk = { ...await exportJWK(ed.publicKey), alg: 'EdDSA', kid: 'trusted' };
const verifier = createVerifier({ issuer, audience, publicKeys: { keys: [jwk] } });

async function sign(changes: Record<string, unknown> = {}, header: Record<string, unknown> = {}) {
  return new SignJWT({
    iss: issuer, aud: audience, sub: 'person', iat: now(), exp: now() + 300,
    apis: { github: ['issues:read'] }, ...changes,
  }).setProtectedHeader({ alg: 'EdDSA', kid: 'trusted', ...header }).sign(ed.privateKey);
}

test('verifies Ed25519 JWTs with typed claims and all constraints', async () => {
  const constraints = { methods: ['GET'], paths: ['/repos/*/issues/*'], query: { state: ['open', null] }, payload: { count: [1, { enabled: true }] } };
  const claims = await verifier(await sign({ constraints }));
  assert.deepEqual(claims.apis, { github: ['issues:read'] });
  assert.deepEqual(claims.constraints, constraints);
});

test('verifies RSA keys of 2048 bits', async () => {
  const rsa = await generateKeyPair('RS256', { modulusLength: 2048, extractable: true });
  const key = { ...await exportJWK(rsa.publicKey), alg: 'RS256', kid: 'rsa' };
  const token = await new SignJWT({ apis: { github: ['issues:read'] } }).setProtectedHeader({ alg: 'RS256', kid: 'rsa' })
    .setIssuer(issuer).setAudience(audience).setSubject('person').setIssuedAt().setExpirationTime('5m').sign(rsa.privateKey);
  assert.equal((await createVerifier({ issuer, audience, publicKeys: { keys: [key] } })(token)).sub, 'person');
});

test('rejects invalid key sets before serving requests', async () => {
  const privateJwk = { ...await exportJWK(ed.privateKey), kid: 'private' };
  const cases: JWK[][] = [
    [], [jwk, jwk], [{ ...jwk, kid: undefined }], [privateJwk],
    [{ ...jwk, alg: 'HS256' }], [{ ...jwk, crv: 'X25519' }],
    [{ ...jwk, key_ops: ['sign'] }], [{ kty: 'oct', k: 'secret', kid: 'symmetric' }],
    [{ kty: 'RSA', kid: 'weak', n: Buffer.alloc(128, 255).toString('base64url'), e: 'AQAB' }],
  ];
  for (const keys of cases) assert.throws(() => createVerifier({ issuer, audience, publicKeys: { keys } }));
});

test('rejects untrusted key ids, substituted signature and issuer/audience', async () => {
  for (const header of [{ kid: 'unknown' }, { kid: undefined }, { jku: 'https://example.test/keys' }, { jwk }]) {
    await assert.rejects(verifier(await sign({}, header)));
  }
  for (const changes of [{ iss: 'other' }, { aud: 'other' }]) await assert.rejects(verifier(await sign(changes)));
  const other = await generateKeyPair('EdDSA', { crv: 'Ed25519' });
  const token = await new SignJWT({ apis: { github: ['issues:read'] } }).setProtectedHeader({ alg: 'EdDSA', kid: 'trusted' })
    .setIssuer(issuer).setAudience(audience).setSubject('person').setIssuedAt().setExpirationTime('5m').sign(other.privateKey);
  await assert.rejects(verifier(token));
  const symmetric = await new SignJWT({ apis: { github: ['issues:read'] } }).setProtectedHeader({ alg: 'HS256', kid: 'trusted' })
    .setIssuer(issuer).setAudience(audience).setSubject('person').setIssuedAt().setExpirationTime('5m').sign(new TextEncoder().encode('not a public signing key'));
  await assert.rejects(verifier(symmetric));
  await assert.rejects(verifier('not.a.token'));
});

test('rejects invalid validity periods and missing or malformed claims', async () => {
  const cases = [
    { exp: now() - 1 }, { exp: now() + 901 }, { iat: now() + 10 }, { iat: undefined },
    { exp: undefined }, { exp: now() }, { nbf: now() + 50 }, { nbf: 'now' },
    { sub: undefined }, { sub: '' }, { iat: 1.5 }, { apis: {} },
    { apis: { github: [] } }, { apis: { github: 'issues:read' } }, { apis: { github: [1] } },
    { apis: { 'bad api': ['read'] } }, { constraints: { methods: ['get'] } },
    { constraints: { methods: [] } }, { constraints: { methods: ['OPTIONS'] } },
    { constraints: { methods: ['CONNECT'] } }, { constraints: { methods: ['TRACE'] } },
    { constraints: { paths: ['/../secret'] } },
    { constraints: { paths: ['/repos/**'] } },
    { constraints: { paths: ['/x/%2e%2e'] } }, { constraints: { query: { q: 'a' } } },
    { constraints: { payload: { x: [] } } }, { constraints: { unknown: true } }, { unknown: true },
  ];
  for (const changes of cases) await assert.rejects(verifier(await sign(changes)), JSON.stringify(changes));
  assert.equal((await verifier(await sign({ nbf: now() - 1 }))).sub, 'person');
});

test('enforces configured maximum lifetime and snapshots trusted keys', async () => {
  const mutable = { ...jwk };
  const verify = createVerifier({ issuer, audience, publicKeys: { keys: [mutable] }, maxTokenLifetimeSeconds: 60 });
  mutable.kid = 'changed';
  await assert.rejects(verify(await sign()));
  assert.equal((await verify(await sign({ exp: now() + 30 }))).sub, 'person');
});

test('safe pathname globs reject traversal, encoded separators and query syntax', () => {
  for (const path of ['/', '/repos/*/issues/*', '/v1/items', '/items/item-*']) assert.equal(isSafePathPattern(path), true, path);
  for (const path of ['x', '//host/path', '/a/../b', '/a/./b', '/%2f', '/a?x=1', '/a#x', '/a\\b', '/a/**x', '/a/**', '/a/[x]', '/a/{x,y}']) assert.equal(isSafePathPattern(path), false, path);
  assert.equal(pathMatches('/repos/example/*', '/repos/example/repository'), true);
  assert.equal(pathMatches('/repos/example/*', '/repos/example/repository/issues'), false);
  assert.equal(pathMatches('/repos/example/*/issues', '/repos/example/repository/issues'), true);
});

test('duration parser bounds token issuance', () => {
  assert.deepEqual(HTTP_METHODS, ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD']);
  assert.equal(parseDuration('15m'), 900);
  assert.equal(parseDuration('30s'), 30);
  for (const duration of ['0', '16m', '1h', '-1', 'Infinity', '15minutes', '1.5m']) assert.throws(() => parseDuration(duration));
});

test('inspection displays expiration and remaining validity, including unverified expired tokens', async () => {
  const expiration = now() + 300;
  const inspected = await inspectToken(await sign({ exp: expiration }));
  assert.equal(inspected.expiresAt, new Date(expiration * 1000).toISOString());
  assert.equal(inspected.expired, false);
  assert.ok(inspected.remainingSeconds !== null && inspected.remainingSeconds > 295 && inspected.remainingSeconds <= 300);
  const past = now() - 10;
  const expired = await inspectToken(await sign({ exp: past }));
  assert.equal(expired.expiresAt, new Date(past * 1000).toISOString());
  assert.equal(expired.expired, true);
  assert.equal(expired.remainingSeconds, 0);
  for (const exp of [undefined, 'not-a-date', Number.MAX_SAFE_INTEGER]) {
    const invalid = await inspectToken(await sign({ exp }));
    assert.equal(invalid.expiresAt, null);
    assert.equal(invalid.expired, null);
    assert.equal(invalid.remainingSeconds, null);
  }
  assert.match(USAGE, /requires --key, --kid, --subject, --api and --permission/u);
});

test('verified constraints integrate with proxy method, path, query and payload semantics', async () => {
  const claims = await verifier(await sign({
    constraints: {
      methods: ['GET'], paths: ['/repos/example/*/issues'],
      query: { state: ['open'], page: [1] }, payload: { 'issue.labels': [['bug']] },
    },
  }));
  const route = { path: '/repos/:owner/:repo/issues', methods: ['GET' as const], permissions: { GET: ['issues:read'] } };
  const context = {
    api: 'github', method: 'GET', path: '/repos/example/repository/issues',
    params: { owner: 'example', repo: 'repository' }, headers: {},
    query: { state: 'open', page: 1 }, body: { issue: { labels: ['bug'] } }, claims,
  };
  assert.doesNotThrow(() => authorize(claims, route, context));
  assert.doesNotThrow(() => authorize(claims, route, { ...context, query: {} }));
  for (const changes of [
    { path: '/repos/example/repository/issues/1' }, { query: { state: 'closed' } },
    { query: { page: '1' } }, { query: { unlisted: 'value' } },
    { body: { issue: { labels: ['enhancement'] } } }, { body: {} },
  ]) assert.throws(() => authorize(claims, route, { ...context, ...changes }));
  const methodsRoute = { ...route, methods: ['POST' as const], permissions: { POST: ['issues:read'] } };
  assert.throws(() => authorize(claims, methodsRoute, { ...context, method: 'POST' }));
});

test('local key generation, multi-API issuance and verified inspection round trip', async () => {
  const directory = join(process.cwd(), `.auth-test-${randomUUID()}`);
  await mkdir(directory, { mode: 0o700 });
  try {
    const keys = await generateKeys(join(directory, 'keys'));
    assert.equal((await stat(keys.privateKeyPath)).mode & 0o777, 0o600);
    assert.equal((await stat(keys.publicKeysPath)).mode & 0o777, 0o600);
    assert.equal((await stat(join(directory, 'keys'))).mode & 0o777, 0o700);
    const original = await readFile(keys.privateKeyPath, 'utf8');
    await assert.rejects(generateKeys(join(directory, 'keys')));
    assert.equal(await readFile(keys.privateKeyPath, 'utf8'), original);
    const registry = join(directory, 'registry.json');
    await writeFile(registry, JSON.stringify([
      { id: 'github', baseUrl: 'https://api.github.com', secretArn: 'secret', authentication: {}, routes: [{ path: '/repos/:owner/:repo/issues', methods: ['GET', 'POST'], permissions: { GET: ['issues:read'], POST: ['issues:write'] } }] },
      { id: 'other', baseUrl: 'https://example.test', secretArn: 'secret', authentication: {}, routes: [{ path: '/items/:id', methods: ['GET'], permissions: { GET: ['items:read'] } }] },
    ]));
    const options = { key: keys.privateKeyPath, kid: keys.kid, subject: 'local-user', registry, issuer, audience, api: ['github', 'other'], permission: ['github:issues:read', 'other:items:read'], methods: ['GET'], paths: ['/repos/*/*/issues'] };
    const token = await createToken(options);
    const inspected = await inspectToken(token, { publicKeys: keys.publicKeysPath, issuer, audience });
    assert.equal(inspected.verified, true);
    assert.equal(inspected.expired, false);
    assert.equal(inspected.expiresAt, new Date(inspected.claims.exp! * 1000).toISOString());
    assert.ok(inspected.remainingSeconds !== null && inspected.remainingSeconds > 895 && inspected.remainingSeconds <= 900);
    assert.deepEqual(inspected.claims.apis, { github: ['issues:read'], other: ['items:read'] });
    assert.equal((inspected.claims as ProxyClaims).exp! - inspected.claims.iat!, 900);
    assert.equal((await inspectToken(token)).verified, false);
    for (const override of [
      { permission: ['github:issues:unknown'] }, { permission: ['other:items:read'], api: ['github'] },
      { api: ['unknown'] }, { paths: ['/../unsafe'] }, { methods: ['DELETE'] }, { methods: ['POST'] }, { expires: '16m' },
    ]) await assert.rejects(createToken({ ...options, ...override }));
    const policy = join(directory, 'policy.json');
    await writeFile(policy, JSON.stringify({ query: { state: ['open'] }, payload: { enabled: [true] } }));
    const policyToken = await createToken({ ...options, policy });
    assert.deepEqual((await inspectToken(policyToken, { publicKeys: keys.publicKeysPath, issuer, audience })).claims.constraints,
      { methods: ['GET'], paths: ['/repos/*/*/issues'], query: { state: ['open'] }, payload: { enabled: [true] } });

    const cli = (...args: string[]) => spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', ...args], {
      cwd: process.cwd(), encoding: 'utf8', env: { ...process.env, JWT_PUBLIC_KEYS: '' },
    });
    const help = cli('--help');
    assert.equal(help.status, 0);
    assert.match(help.stdout, /requires --key, --kid, --subject, --api and --permission/u);
    const output = join(directory, 'token.jwt');
    const arguments_ = ['token', 'create', '--key', keys.privateKeyPath, '--kid', keys.kid,
      '--subject', 'local-user', '--api', 'github', '--permission', 'github:issues:read',
      '--registry', registry, '--issuer', issuer, '--audience', audience, '--methods', 'GET', '--output', output];
    const created = cli(...arguments_);
    assert.equal(created.status, 0, created.stderr);
    assert.equal(created.stdout, '');
    assert.equal((await stat(output)).mode & 0o777, 0o600);
    const contents = await readFile(output, 'utf8');
    assert.notEqual(cli(...arguments_).status, 0);
    assert.equal(await readFile(output, 'utf8'), contents);
    const inspectedCli = cli('token', 'inspect', '--file', output, '--public-keys', keys.publicKeysPath, '--issuer', issuer, '--audience', audience);
    assert.equal(inspectedCli.status, 0, inspectedCli.stderr);
    assert.equal(JSON.parse(inspectedCli.stdout).verified, true);
    const stdin = spawnSync(process.execPath, ['--import', 'tsx', 'src/cli/index.ts', 'token', 'inspect'], {
      input: token, encoding: 'utf8', env: { ...process.env, JWT_PUBLIC_KEYS: '' },
    });
    assert.equal(stdin.status, 0, stdin.stderr);
    assert.equal(JSON.parse(stdin.stdout).verified, false);
    assert.deepEqual((await readdir(directory)).filter(name => name.endsWith('.pending')), []);
  } finally { await rm(directory, { recursive: true, force: true }); }
});

test('key generation supports RSA and leaves existing public files untouched', async () => {
  const directory = join(process.cwd(), `.auth-test-${randomUUID()}`);
  await mkdir(directory, { mode: 0o700 });
  try {
    await writeFile(join(directory, 'public.jwks.json'), 'existing', { mode: 0o600 });
    await assert.rejects(generateKeys(directory, 'RS256'));
    assert.equal(await readFile(join(directory, 'public.jwks.json'), 'utf8'), 'existing');
    assert.deepEqual(await readdir(directory), ['public.jwks.json']);
    await rm(join(directory, 'public.jwks.json'));
    const keys = await generateKeys(directory, 'RS256');
    const jwks = JSON.parse(await readFile(keys.publicKeysPath, 'utf8'));
    assert.equal(jwks.keys[0].alg, 'RS256');
    assert.equal(jwks.keys[0].d, undefined);
    assert.equal(Buffer.from(jwks.keys[0].n, 'base64url').length, 256);
  } finally { await rm(directory, { recursive: true, force: true }); }
});
