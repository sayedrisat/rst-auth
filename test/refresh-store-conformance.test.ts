import { describe, it } from "vitest";
import { MemoryRefreshTokenStore } from "../src/memory-refresh-token-store.js";
import { registerRefreshTokenStoreConformanceTests } from "../src/testing/refresh-store-conformance.js";

describe("MemoryRefreshTokenStore conformance", () => {
  registerRefreshTokenStoreConformanceTests(
    { test: (name, fn) => it(name, fn) },
    () => new MemoryRefreshTokenStore(),
  );
});
