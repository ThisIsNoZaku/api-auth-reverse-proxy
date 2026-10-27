import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { test } from 'node:test';
import { App } from 'aws-cdk-lib';
import { Template } from 'aws-cdk-lib/assertions';
import { defaults, parseConfig } from '../../infrastructure/cdk/config.js';
import { ProxyStack } from '../../infrastructure/cdk/stack.js';

const secretArn = 'arn:aws:secretsmanager:us-east-1:123456789012:secret:example-api-AbCdEf';
const kmsArn = 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012';
const input = {
  registry: [{
    id: 'example', baseUrl: 'https://api.example.com', secretArn,
    authentication: { type: 'bearer' },
    routes: [{ path: '/status', methods: ['GET'], permissions: { GET: ['status:read'] } }],
  }],
  publicKeys: { keys: [{ ...generateKeyPairSync('ed25519').publicKey.export({ format: 'jwk' }), kid: 'public-only' }] },
};

function synth(overrides: Record<string, unknown> = {}) {
  const directory = resolve(`dist/infrastructure-test-${process.pid}-${Math.random().toString(36).slice(2)}`);
  mkdirSync(directory, { recursive: true });
  const artifact = resolve(directory, 'lambda.zip');
  writeFileSync(artifact, Buffer.from('504b0506000000000000000000000000000000000000', 'hex'));
  try {
    const app = new App({ outdir: resolve(directory, 'cdk.out') });
    const stack = new ProxyStack(app, 'TestProxy', {
      env: { account: '123456789012', region: 'us-east-1' },
      config: parseConfig({ ...input, ...overrides }),
      artifactPath: artifact,
    });
    app.synth();
    return Template.fromStack(stack);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('CDK actually synthesizes a Node 24 HTTP API using the prebuilt asset', () => {
  const template = synth();
  template.resourceCountIs('AWS::Lambda::Function', 1);
  template.hasResourceProperties('AWS::Lambda::Function', {
    Runtime: 'nodejs24.x', Handler: 'index.handler', Architectures: ['arm64'],
    MemorySize: 256, Timeout: 30, ReservedConcurrentExecutions: 10,
    Environment: { Variables: {
      API_REGISTRY: JSON.stringify(input.registry), JWT_PUBLIC_KEYS: JSON.stringify(input.publicKeys),
      JWT_ISSUER: 'local-token-issuer', JWT_AUDIENCE: 'multi-api-proxy',
    } },
  });
  template.hasResourceProperties('AWS::ApiGatewayV2::Api', { ProtocolType: 'HTTP' });
  template.hasResourceProperties('AWS::ApiGatewayV2::Route', { RouteKey: '$default', AuthorizationType: 'NONE' });
  template.hasResourceProperties('AWS::ApiGatewayV2::Integration', { PayloadFormatVersion: '2.0', IntegrationType: 'AWS_PROXY' });
  template.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
    StageName: '$default', AutoDeploy: true,
    DefaultRouteSettings: { ThrottlingRateLimit: 20, ThrottlingBurstLimit: 10 },
  });
  template.resourceCountIs('AWS::Logs::LogGroup', 2);
  for (const resource of Object.values(template.findResources('AWS::Logs::LogGroup'))) {
    assert.equal(resource.Properties.RetentionInDays, 30);
  }
  const stages = Object.values(template.findResources('AWS::ApiGatewayV2::Stage'));
  assert.deepEqual(JSON.parse(stages[0]!.Properties.AccessLogSettings.Format), {
    requestId: '$context.requestId', status: '$context.status',
    responseLatency: '$context.responseLatency', integrationLatency: '$context.integrationLatency',
  });
  template.resourceCountIs('AWS::CloudWatch::Alarm', 4);
  template.hasResourceProperties('AWS::CloudWatch::Alarm', { MetricName: 'Duration', Threshold: 24000 });
  template.hasResourceProperties('AWS::CloudWatch::Alarm', {
    Namespace: 'AWS/ApiGateway', MetricName: '5xx', Statistic: 'Sum', Threshold: 1,
  });
  assert.ok(template.toJSON().Outputs.proxyurl);
  const functions = Object.values(template.findResources('AWS::Lambda::Function'));
  assert.ok(functions[0]!.Properties.Code.S3Key);
});

test('IAM grants only exact registry secret reads and opt-in constrained KMS decryption', () => {
  for (const kmsKeyArns of [[], [kmsArn]]) {
    const template = synth({ kmsKeyArns, registry: [...input.registry, { ...input.registry[0], id: 'second-api' }] });
    const statements = Object.values(template.findResources('AWS::IAM::Policy'))
      .flatMap((resource) => resource.Properties.PolicyDocument.Statement as Record<string, unknown>[]);
    const secret = statements.find((statement) => JSON.stringify(statement.Action).includes('secretsmanager'));
    assert.ok(secret);
    assert.equal(secret.Action, 'secretsmanager:GetSecretValue');
    assert.equal(secret.Resource, secretArn);
    const kms = statements.find((statement) => JSON.stringify(statement.Action).includes('kms:'));
    assert.equal(Boolean(kms), kmsKeyArns.length > 0);
    if (kms) {
      assert.equal(kms.Action, 'kms:Decrypt');
      assert.equal(kms.Resource, kmsArn);
      assert.deepEqual(kms.Condition, { StringEquals: { 'kms:ViaService': {
        'Fn::Join': ['', ['secretsmanager.us-east-1.', { Ref: 'AWS::URLSuffix' }]],
      } } });
    }
  }
});

test('nondefault operational and authentication settings survive synthesis', () => {
  const template = synth({
    environment: 'staging', issuer: 'https://issuer.example.com', audience: 'custom-proxy',
    memorySize: 512, timeoutSeconds: 15, reservedConcurrency: 5,
    rateLimit: 12, burstLimit: 4, logRetentionDays: 7, durationAlarmThresholdMs: 9000,
  });
  template.hasResourceProperties('AWS::Lambda::Function', {
    FunctionName: 'api-auth-proxy-cdk-staging',
    MemorySize: 512, Timeout: 15, ReservedConcurrentExecutions: 5,
    Environment: { Variables: {
      API_REGISTRY: JSON.stringify(input.registry), JWT_PUBLIC_KEYS: JSON.stringify(input.publicKeys),
      JWT_ISSUER: 'https://issuer.example.com', JWT_AUDIENCE: 'custom-proxy',
    } },
  });
  template.hasResourceProperties('AWS::ApiGatewayV2::Integration', { TimeoutInMillis: 15000 });
  template.hasResourceProperties('AWS::ApiGatewayV2::Stage', {
    DefaultRouteSettings: { ThrottlingRateLimit: 12, ThrottlingBurstLimit: 4 },
  });
  template.hasResourceProperties('AWS::CloudWatch::Alarm', { MetricName: 'Duration', Threshold: 9000 });
  for (const resource of Object.values(template.findResources('AWS::Logs::LogGroup'))) {
    assert.equal(resource.Properties.RetentionInDays, 7);
  }
});

test('deployment configuration rejects wildcard ARNs, private keys, and unsafe numeric limits', () => {
  for (const secretArn of ['*', `${input.registry[0]!.secretArn}*`, 'arn:aws:secretsmanager:*:123456789012:secret:example']) {
    assert.throws(() => parseConfig({ ...input, registry: [{ secretArn }] }), /exact/);
  }
  for (const field of ['d', 'p', 'q', 'dp', 'dq', 'qi', 'oth', 'k']) {
    assert.throws(() => parseConfig({ ...input, publicKeys: { keys: [{ kty: 'RSA', [field]: 'do-not-deploy' }] } }), /public keys/);
  }
  assert.throws(() => parseConfig({ ...input, publicKeys: { keys: [{ kty: 'oct', k: 'secret' }] } }), /public keys/);
  assert.throws(() => parseConfig({ ...input, publicKeys: { keys: [{ kty: 'EC', kid: 'unsupported', crv: 'P-256' }] } }), /public keys/);
  assert.throws(() => parseConfig({ ...input, publicKeys: { keys: [{ ...input.publicKeys.keys[0], kid: undefined }] } }), /valid/);
  assert.throws(() => parseConfig({ ...input, publicKeys: { keys: [{ kty: 'RSA', kid: 'bad', n: 'weak', e: 'AQAB' }] } }), /valid/);
  assert.throws(() => parseConfig({ ...input, publicKeys: { keys: [input.publicKeys.keys[0], input.publicKeys.keys[0]] } }), /valid/);
  assert.throws(() => parseConfig({ ...input, audience: 'é'.repeat(4096) }), /4096-byte/);
  assert.throws(() => parseConfig({ ...input, registry: [{ ...input.registry[0], baseUrl: 'http://api.example.com' }] }), /registry/);
  assert.throws(() => parseConfig({ ...input, registry: [{ ...input.registry[0], secretValue: 'must-not-be-in-configuration' }] }), /registry/);
  assert.throws(() => parseConfig({ ...input, kmsKeyArns: ['*'] }), /exact/);
  assert.throws(() => parseConfig({ ...input, timeoutSeconds: 31 }), /timeoutSeconds/);
  assert.throws(() => parseConfig({ ...input, reservedConcurrency: 0 }), /reservedConcurrency/);
  assert.throws(() => parseConfig({ ...input, logRetentionDays: 2 }), /retention/);
  assert.equal(parseConfig({ ...input, timeoutSeconds: 10 }).durationAlarmThresholdMs, 8000);
  const example = JSON.parse(readFileSync('config/apis/example.json', 'utf8'));
  assert.doesNotThrow(() => parseConfig({ ...input, registry: example }));
  const rsa = generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' });
  assert.doesNotThrow(() => parseConfig({ ...input, publicKeys: { keys: [{ ...rsa, kid: 'rsa-key', alg: 'RS256' }] } }));
});

test('CDK and Terraform defaults and deployment contracts remain in parity', () => {
  const variables = readFileSync('infrastructure/terraform/variables.tf', 'utf8');
  for (const [camelName, value] of Object.entries(defaults)) {
    const snakeName = camelName.replace(/[A-Z]/g, (letter) => `_${letter.toLowerCase()}`);
    const declaration = variables.match(new RegExp(`variable "${snakeName}" \\{([\\s\\S]*?)(?=\\nvariable |$)`));
    assert.ok(declaration, `Terraform declares ${snakeName}`);
    const actual = declaration[1]!.match(/default\s*=\s*("[^"]*"|\d+)/);
    assert.ok(actual, `Terraform defaults ${snakeName}`);
    assert.equal(JSON.parse(actual[1]!), value, `${snakeName} default parity`);
  }
  const terraform = readFileSync('infrastructure/terraform/main.tf', 'utf8');
  for (const fragment of [
    'dist/lambda.zip', 'nodejs24.x', 'index.handler', '["arm64"]',
    'payload_format_version = "2.0"', 'route_key          = "$default"',
    'authorization_type = "NONE"', 'API_REGISTRY', 'JWT_PUBLIC_KEYS', 'JWT_ISSUER', 'JWT_AUDIENCE',
    'secretsmanager:GetSecretValue', 'Resource = local.secret_arns', 'kms:ViaService',
    'var.timeout_seconds * 800', 'throttling_rate_limit', 'throttling_burst_limit',
  ]) assert.ok(terraform.includes(fragment), `Terraform contract: ${fragment}`);
  assert.match(terraform, /Errors\s*=/);
  assert.match(terraform, /Throttles\s*=/);
  assert.match(terraform, /Duration\s*=/);
  assert.match(terraform, /namespace\s*=\s*"AWS\/ApiGateway"/);
  assert.match(terraform, /metric_name\s*=\s*"5xx"/);
  const logFormat = terraform.match(/format = jsonencode\(\{([\s\S]*?)\}\)/)![1]!;
  assert.deepEqual([...logFormat.matchAll(/\$context\.([A-Za-z]+)/g)].map((match) => match[1]).sort(),
    ['integrationLatency', 'requestId', 'responseLatency', 'status']);
  assert.match(readFileSync('infrastructure/terraform/outputs.tf', 'utf8'), /output "proxy_url"/);
  assert.ok(variables.includes('["d", "p", "q", "dp", "dq", "qi", "oth", "k"]'));
});

test('Lambda packaging is deterministic and bundles the runtime SDK into one ESM entrypoint', () => {
  function packageLambda() {
    const result = spawnSync(process.execPath, ['--import', 'tsx', 'scripts/package-lambda.ts'], { encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
    return createHash('sha256').update(readFileSync('dist/lambda.zip')).digest('hex');
  }
  const firstHash = packageLambda();
  assert.equal(packageLambda(), firstHash);
  const listing = spawnSync('unzip', ['-Z1', 'dist/lambda.zip'], { encoding: 'utf8' });
  assert.equal(listing.status, 0, listing.stderr);
  assert.equal(listing.stdout.trim(), 'index.mjs');
  const bundled = readFileSync('dist/lambda-bundle/index.mjs', 'utf8');
  assert.ok(!/\bfrom\s*["']@aws-sdk\//.test(bundled));
  assert.match(bundled, /SecretsManagerClient/);
  assert.match(bundled, /export\s*\{[\s\S]*handler/);
  const load = spawnSync(process.execPath, ['--input-type=module', '-e',
    'const { handler } = await import("./dist/lambda-bundle/index.mjs"); if (typeof handler !== "function") process.exit(1);',
  ], { encoding: 'utf8' });
  assert.equal(load.status, 0, load.stderr);
});
