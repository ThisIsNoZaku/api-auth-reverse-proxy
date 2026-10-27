# Stateless multi-API authentication proxy

Give an AI agent a short-lived JWT, not your upstream API keys. One Node.js 24 Lambda
handles `https://YOUR_PROXY/{apiId}/{path}` for every registered API. API Gateway HTTP
API invokes the Lambda; the application verifies JWTs, enforces route permissions
and request policies, reads the API's credential from Secrets Manager, and forwards
using native `fetch`. There is no token service, database, OAuth, or refresh mechanism.

## Setup

Prerequisites: Node.js 24+, npm, `zip`/`unzip`, AWS CLI credentials for deployment,
and **either** AWS CDK v2 (included as a dev dependency) or Terraform 1.7+ with AWS
provider 6.x. Local token operations do not require AWS access.

```sh
npm ci
npm run check
npm test
npm run test:terraform    # requires terraform; initializes the AWS provider, no AWS deployment
```

Tests use Node's test runner. They cover authentication/CLI, policy evaluation,
validation, mocked Secrets Manager, and HTTP mock upstreams. The integration test
injects a test-only transport mapping a fixed HTTPS origin to a loopback HTTP
server; production accepts only registered HTTPS upstreams. Infrastructure tests
actually synthesize CDK, compare deployment contracts, and build the ZIP twice to
check determinism. CI runs these checks without AWS credentials. Tests are not a
claim that an AWS deployment or real GitHub request has been exercised.

## 1. Generate local signing keys

```sh
npm run auth -- keys generate --directory .auth-keys/current
# JSON output includes kid, privateKeyPath and publicKeysPath.
```

This generates Ed25519 keys by default. `--algorithm RS256` generates a 2048-bit RSA
pair. Directories must have mode `0700`; private files use `0600`. Existing keys
are never overwritten. Keep `private.pem` **only on your local machine**, outside
deployment inputs and build directories. Back it up securely. Do not copy it to
Lambda, Secrets Manager, Terraform variables/state, CDK context, or agents.
`public.jwks.json` is the public verification configuration and may be deployed.
Git ignores the default key directory and PEM/key/token files.

## 2. Create and populate upstream secrets

Create empty secrets separately; the deployment frameworks reference existing
**complete** secret ARNs and never create secret values:

```sh
aws secretsmanager create-secret --name agent-proxy/github
# Copy the returned ARN into your registry.
# /secure/github-token.txt contains just the upstream token; do not commit it.
aws secretsmanager put-secret-value \
  --secret-id YOUR_COMPLETE_SECRET_ARN \
  --secret-string file:///secure/github-token.txt
```

The default is a raw SecretString (SecretBinary UTF-8 is also supported).
For a JSON secret such as `{"key":"..."}`, set `authentication.secretField` to
`"key"`. Secret values must be nonempty printable ASCII, without newlines.
Trim trailing newlines in the securely prepared credential file. Prefer
fine-grained, API-scoped upstream credentials. For customer-managed encryption,
provide exact KMS key ARNs in `kmsKeyArns`/`kms_key_arns`; decryption is constrained
to Secrets Manager in the configured region.

## 3. Register APIs and policies

Start with `config/apis/example.json`. It contains two independent registrations:
GitHub bearer authentication and an example API-key service. Replace the account,
region, and secret ARNs; remove/replace the illustrative service before deployment.
Use the **same registry JSON** for the CLI and your chosen deployment.

Each API declares:

| Field | Behavior |
| --- | --- |
| `id`, `baseUrl`, `secretArn` | Unique identifier, fixed HTTPS base URL (optional path prefix), exact secret ARN |
| `authentication` | `{type:"bearer"}`, or `{type:"apiKey"\|"custom",header:"lowercase-name",prefix?:"..."}`; optional `secretField` |
| `routes` | Exact segment patterns such as `/repos/:owner/:repo/issues`; allowed methods and required named permissions per method |
| `params` | Schema for **every** named path parameter |
| `query` | `allowed`, optional `required`, `parameters` schemas, and `unknown:"reject"\|"filter"` |
| `headers` | Lowercase `allowed`, optional `required`/`schemas`, `unknown:"reject"\|"filter"` |
| `body` | `mode:"json"\|"binary"`, optional `required`, `contentTypes`; JSON requires `schema` |
| `policies` | Additional allow/deny conditions described below |
| `maxPayloadBytes` | Default 1,000,000; maximum 4,000,000 |
| `maxResponseBytes` | Default/maximum 4,000,000 |
| `timeoutMs` | Default 10,000; maximum 25,000, including secret lookup and response reading |
| `responseHeaders` | Optional subset of the built-in safe response-header allowlist |

Methods: GET, POST, PUT, PATCH, DELETE, HEAD. GET/HEAD bodies are rejected (native
fetch does not support them). A body is rejected unless explicitly registered;
binary routes can restrict accepted content types without JSON parsing.

Schemas use a small, strongly typed JSON-declarable vocabulary compiled to **Zod**:
`string` (`enum`, `pattern`, `minLength`, `maxLength`), `number`/`integer`
(`minimum`, `maximum`), `boolean`, `null`, `array` (`items`, `minItems`, `maxItems`),
and `object` (`properties`, `required`, `unknown`). Objects reject unknown fields
by default, recursively. Set `unknown:"filter"` explicitly to remove them.
Patterns are trusted administrator-authored regular expressions; keep them
bounded and avoid pathological expressions. This vocabulary is not a full
JSON Schema implementation.

Query/header values are strings unless a numeric/boolean query or header schema
is declared. Policy conditions and JWT query constraints see their **typed** values;
forwarding retains the original strings. Unknown query parameters are rejected,
including on routes without a query configuration. Default forwarded request
headers are `accept` and `content-type`; other application headers must be
registered. Client metadata is stripped. Caller authorization, cookies, API keys,
forwarding headers, configured credential headers, and hop-by-hop headers are
never forwarded. Response headers default to content type, cache metadata,
retry-after, and rate-limit metadata; cookies, location, auth, length and encoding
headers are stripped. Redirects are returned without following or exposing Location.

Unknown APIs/routes/methods are denied. Route selection favors literal segments;
equally specific matching patterns fail closed. Path parameters cannot contain
encoded slashes, backslashes, percent escapes after decoding, dot segments,
control characters, or duplicate separators. Duplicate query names (including
encoded aliases), malformed encoding, duplicate JSON object keys (including
escaped aliases), prototype keys, non-finite numbers and unsafe integers are
rejected. JSON parsing has depth/node limits. JSON must be valid UTF-8 without a
BOM; conflicting/non-UTF-8 charsets and non-identity JSON content encodings fail.

### Combined policies

Conditions support `allOf`, `anyOf`, `not`, and predicates:
`{field,op,value}` or `{field,op,otherField}`. Fields select dotted paths in
`api`, `method`, `path`, `params`, `query`, `headers`, `body`, and `claims`, including
array indices (`body.items.0.owner`). Operations are `eq`, `in`, `contains`
(array membership), `matches`, `exists`, `lt`, `lte`, `gt`, `gte`.
All matching deny rules take precedence; if any allow rules exist, at least one
must match. Route permissions remain required regardless of policy results.

For example, require a POST payload owner to equal the path owner, but permit GET:

```json
{
  "effect": "allow",
  "condition": {
    "anyOf": [
      {"field":"method","op":"eq","value":"GET"},
      {"allOf":[
        {"field":"method","op":"eq","value":"POST"},
        {"field":"body.owner","op":"eq","otherField":"params.owner"}
      ]}
    ]
  }
}
```

Include `owner` in the registered payload schema if using this example.
Use a conditional `exists` policy to require a body only on certain methods.
Do not set `body.required:true` on a shared GET/POST route unless both should
require a body.

### Explicit TypeScript extensions

Ordinary APIs require only registry configuration, a secret, and redeployment.
For custom logic, `config/apis/extensions.ts` is a trusted build-time extension
point that returns the registry. Assign a route's `validate(context):boolean`,
`transform(context):context`, or an API's `filterResponse(buffer,headers):Buffer`.
For example, a JSON route can normalize a title:

```ts
route.transform = context => ({
  ...context,
  body: { ...(context.body as {title:string}), title: (context.body as {title:string}).title.trim() }
});
```

Transformations cannot change API, method, path, path parameters or claims.
Output headers/query/body are revalidated; optional `body.outputSchema` specifies
a deliberately different output shape. Permissions, JWT constraints and policies
run both before and after transformation. Custom validators receive isolated
copies. Response filters only receive safe response headers. Changes to trusted
TypeScript hooks require rebuilding the shared artifact.

Without explicit filtering/transformation, original JSON whitespace, binary
bytes, query encoding/order, method, and content type are preserved. Normal
transport differences (host, content length, compression, and hop-by-hop headers)
are handled by fetch/API Gateway, not copied blindly.

## 4. Issue and inspect short-lived tokens

Copy the `kid` from key generation (or read it from the public JWKS).
Permissions are **explicit**: each `--permission` is `API:permission-name`.

```sh
KID=$(node -p "JSON.parse(require('fs').readFileSync('.auth-keys/current/public.jwks.json')).keys[0].kid")
TOKEN=$(npm run --silent auth -- token create \
  --key .auth-keys/current/private.pem --kid "$KID" \
  --subject codex-agent --expires 15m \
  --registry config/apis/example.json \
  --api github --permission github:issues:read --permission github:issues:create \
  --methods GET,POST --paths "/repos/example/*/issues")

printf '%s' "$TOKEN" | npm run --silent auth -- token inspect \
  --public-keys .auth-keys/current/public.jwks.json
```

Repeat `--api` and `--permission` for multiple APIs. Defaults:
issuer `local-token-issuer`, audience `multi-api-proxy`, expiry 15 minutes;
override `--issuer`, `--audience`, or `JWT_ISSUER`/`JWT_AUDIENCE`. Lifetimes are
capped at 15 minutes. The CLI rejects unknown/unselected permissions and methods
unavailable under the granted permissions. Wildcards are single-segment `*`
(not recursive `**`): `/repos/example/*` does **not** match an issues subpath.

`--policy /secure/constraints.json` accepts a constraints object, for example:

```json
{
  "methods": ["POST"],
  "paths": ["/repos/example/project/issues"],
  "query": {"page":[1,2],"state":["open"]},
  "payload": {"labels.0":["agent-created"]}
}
```

JWT restrictions only narrow server policy. Query constraints are an allowlist
for supplied keys/values, not a requirement to supply those keys. Payload
selectors must exist and equal one of the specified values. CLI `--methods`
and `--paths` override those corresponding fields in the policy file.

Tokens go only to stdout by default. `--clipboard` uses an installed OS clipboard
tool (`pbcopy`, `clip.exe`, `wl-copy`, or `xclip`); consider clipboard-manager risks.
`--output /secure/token.jwt` is explicit opt-in storage, uses mode `0600`, and
never overwrites. Do not enable shell tracing while handling tokens.
Inspect accepts stdin or `--file`. Without public keys it clearly labels decoded
claims **UNVERIFIED**; with keys it verifies signature, kid, algorithm, issuer,
audience and validity. Expired/invalid verified tokens cause a nonzero exit.

## 5. Build the shared Lambda artifact

```sh
npm run build
```

`scripts/package-lambda.ts` uses esbuild to bundle the handler and runtime
dependencies, including the AWS SDK, into `dist/lambda.zip` (`index.mjs`).
ZIP order, file mode and timestamps are fixed; identical inputs produce the
same artifact. Neither private keys nor credential files are read or packaged.
Both deployment frameworks consume **this exact ZIP**. Generated `dist/` and
CDK output are ignored by Git.

## 6. Deploy with CDK (choose one framework)

Create the ignored `deployment.json` from public configuration only:

```sh
node --input-type=module -e '
import fs from "node:fs";
fs.writeFileSync("deployment.json", JSON.stringify({
  region:"us-east-1", environment:"dev",
  registry:JSON.parse(fs.readFileSync("config/apis/example.json","utf8")),
  publicKeys:JSON.parse(fs.readFileSync(".auth-keys/current/public.jwks.json","utf8"))
}, null, 2));
'
npx cdk bootstrap aws://YOUR_ACCOUNT_ID/us-east-1
npm run deploy:cdk -- -c config=deployment.json
# Stack output proxyurl contains https://...execute-api...amazonaws.com
```

Optional JSON settings: `issuer`, `audience`, `memorySize` (256),
`timeoutSeconds` (30), `reservedConcurrency` (10), `rateLimit` (20),
`burstLimit` (10), `logRetentionDays` (30), `durationAlarmThresholdMs`
(80% of Lambda timeout), and `kmsKeyArns` ([]). Keep Lambda/API timeout above
the registry's per-API timeout. AWS account concurrency quotas can prevent even
a small reservation; adjust the account quota or reservation before deployment.

## 7. Deploy with Terraform (alternative)

```sh
cp infrastructure/terraform/terraform.tfvars.example infrastructure/terraform/terraform.tfvars
# Edit registry_json and public_keys_json with the same registry/public JWKS as CDK.
npm run deploy:terraform
# Terraform output proxy_url contains the proxy endpoint.
```

Variables use the equivalent snake_case settings (`memory_size`,
`timeout_seconds`, `reserved_concurrency`, `rate_limit`, `burst_limit`,
`log_retention_days`, `duration_alarm_threshold_ms`, `kms_key_arns`), plus
`region`, `environment`, `registry_json`, `public_keys_json`, `issuer`, `audience`.
Use an encrypted, access-controlled remote Terraform backend for production,
with locking appropriate to your backend. Commit your reviewed provider lock
file after `terraform init`; do not commit state, plans, or credential values.
No `aws_secretsmanager_secret_version` resources are used.

CDK names resources `api-auth-proxy-cdk-ENV`; Terraform uses
`api-auth-proxy-tf-ENV`. Both provision a single ARM64 Node.js Lambda, catch-all
HTTP API, scoped secret-read IAM, opt-in KMS decrypt permissions, logs, throttling,
concurrency, alarms and URL output. Configuration is public-only; it is present
in templates/state. Lambda's **4 KiB total environment-variable limit** bounds
registry plus public JWKS size; keep configuration compact. Large registries
need a separately designed trusted configuration distribution mechanism.

## 8. Configure an agent and call the proxy

Give the agent the proxy base URL and JWT through its short-lived secret/config
input, and instruct it to select `/{apiId}/...`. Do not give it signing keys,
AWS credentials, upstream tokens, or the ability to mint additional JWTs.
Hostnames in the upstream registry are administrator-controlled; callers cannot
supply destinations. If you need `proxy.example.com`, provision an API Gateway
custom domain, certificate and DNS mapping separately; the default deployment
outputs the working AWS HTTPS endpoint.

```sh
PROXY_URL=https://YOUR_API_ID.execute-api.us-east-1.amazonaws.com
AUTH_HEADER=$(printf 'Authorization: %s %s' Bearer "$TOKEN")
curl --fail-with-body "$PROXY_URL/github/repos/example/project/issues?state=open" \
  -H "$AUTH_HEADER"
curl --fail-with-body -X POST "$PROXY_URL/github/repos/example/project/issues" \
  -H "$AUTH_HEADER" -H 'Content-Type: application/json' \
  --data-binary '{"title":"Example issue","labels":["agent-created"]}'
# Binary routes: --data-binary @file.bin and the registered content type.
unset TOKEN AUTH_HEADER
```

Avoid verbose curl logging, shared process inspection, and recording agent
request headers. curl examples are for an API/owner/repository you control.

## Rotation, limits, monitoring and troubleshooting

- **Signing keys:** generate into a new local directory. Add the new public JWK
  alongside the old one (unique kids), redeploy, then issue with the new private
  key/kid. After the longest issued lifetime, remove the old public key and
  redeploy. Only Ed25519/EdDSA and RSA/RS256 keys are accepted; public JWKS must
  not contain private fields. Tokens require trusted `kid`, `iss`, `aud`, `sub`,
  `iat`, `exp`; optional `nbf` is enforced, future-issued and overlong tokens fail.
- **JWT revocation:** individual tokens **cannot be revoked before expiration**
  without adding state. Removing a public key invalidates every token signed by
  that key after configuration rollout. No refresh or self-vending endpoint exists.
- **Upstream rotation:** update the secret's AWSCURRENT value. Warm Lambdas cache
  credentials for 60 seconds; expiry reloads without redeployment. Upstream
  401/403 invalidates the cache for the next request. Requests are not retried
  automatically, avoiding duplicate side effects.
- **Payloads:** requests and responses are bounded to 4,000,000 bytes to leave
  room for base64/event overhead under Lambda's synchronous 6 MiB limit (HTTP
  API's separate limit is 10 MB). Bodies stream-read with a response cap.
  Responses are base64 encoded for API Gateway; content type is retained, and
  fetch-decompressed content is returned without stale content-encoding/length.
  This is buffered proxying, not streaming/WebSocket/multipart transformation.
- **Monitoring:** CloudWatch access logs contain only request ID, status and
  latency; JWTs, query strings, payloads and upstream credentials are not logged.
  Lambda error/throttle/duration and HTTP API 5xx alarms are provisioned; connect
  alarm actions to your own notification system. Application rejections are HTTP
  responses, not unhandled Lambda errors; inspect API status metrics/access logs.
- **Troubleshooting:** 401 means invalid/missing/expired JWT; 403 means permission
  or constraint denial; 400/405/413/415 means registry input validation; 502 means
  upstream/credential failure or oversized response; 504 means timeout.
  Unexpected 500 `configuration_error` means deployment configuration is invalid.
  Detailed upstream/SDK exceptions are intentionally not returned. Check secret
  ARNs, permissions, region, public keys, issuer/audience, size and quotas locally
  rather than adding sensitive logging.
- **Costs:** pay-per-use HTTP API, Lambda, Secrets Manager reads/storage and
  CloudWatch logging; no NAT gateway, database or always-on compute. Caching
  reduces Secrets Manager calls. Set account budgets, appropriately low
  throttling/concurrency, and suitable log retention.

## Destroy and migrate

```sh
npm run destroy:cdk -- -c config=deployment.json
# OR, for a Terraform deployment:
npm run destroy:terraform
```

Secrets were created separately and survive either destroy command. CDK retains
log groups by default; Terraform destroys its managed log groups. Review retained
CDK logs/assets and Terraform state backups according to your retention policy.

**Never let CDK and Terraform manage the same resources.** CloudFormation stacks
and Terraform state are independent ownership systems. For migration, deploy the
other framework under its distinct resource names/environment using the same
public configuration, existing secrets and artifact, smoke-test it with a
short-lived token, switch agent URLs/DNS, and then destroy the old deployment.
Avoid resource imports/adoption without a reviewed state/retention migration
plan; simply running both against the same physical resources is not migration.
