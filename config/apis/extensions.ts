import type { Registry } from "../../src/registry/index.js";

// Optional, trusted TypeScript hooks. Registry JSON alone is sufficient for ordinary APIs.
export function configureRegistry(registry: Registry): Registry {
  return registry;
}
