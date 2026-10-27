import { chmod, mkdir, rename, rm, utimes } from 'node:fs/promises';
import { resolve } from 'node:path';
import { spawnSync } from 'node:child_process';
import { build } from 'esbuild';

const directory = resolve('dist/lambda-bundle');
const artifact = resolve('dist/lambda.zip');
const archive = resolve(directory, 'lambda.zip');
await mkdir(directory, { recursive: true });
await build({
  entryPoints: ['src/proxy/handler.ts'],
  outfile: resolve(directory, 'index.mjs'),
  bundle: true,
  packages: 'bundle',
  platform: 'node',
  target: 'node24',
  format: 'esm',
  charset: 'utf8',
  legalComments: 'none',
  sourcemap: false,
  minify: false,
  banner: { js: 'import { createRequire } from "node:module"; const require = createRequire(import.meta.url);' },
});
const output = resolve(directory, 'index.mjs');
await chmod(output, 0o644);
const fixedTime = new Date('2000-01-01T00:00:00.000Z');
await utimes(output, fixedTime, fixedTime);
await rm(archive, { force: true });
const result = spawnSync('zip', ['-X', '-q', archive, 'index.mjs'], {
  cwd: directory, stdio: 'inherit', env: { ...process.env, TZ: 'UTC' },
});
if (result.error) throw result.error;
if (result.status !== 0) throw new Error(`zip failed with exit status ${result.status}`);
await rename(archive, artifact);
console.log('Packaged dist/lambda.zip');
