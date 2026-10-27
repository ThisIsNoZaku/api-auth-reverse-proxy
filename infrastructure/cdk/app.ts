import { resolve } from 'node:path';
import { App } from 'aws-cdk-lib';
import { loadConfig } from './config.js';
import { ProxyStack } from './stack.js';

const app = new App();
const configPath: unknown = app.node.tryGetContext('config');
if (typeof configPath !== 'string' || configPath.length === 0) {
  throw new Error('Pass -c config=path/to/deployment.json (registry and publicKeys must contain public configuration only)');
}
const config = loadConfig(resolve(configPath));
new ProxyStack(app, `ApiAuthProxyCdk-${config.environment}`, {
  env: { region: config.region },
  config,
});
