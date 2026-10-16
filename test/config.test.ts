import { describe, expect, it } from "vitest";
import { createAuth } from "../src/index.js";
import type { AuthConfig } from "../src/config.js";

const key = new TextEncoder().encode("0123456789abcdef0123456789abcdef");

describe("createAuth configuration", () => {
  it("applies safe defaults and accepts injected config", () => {
    expect(() => createAuth({ accessToken: { key } })).not.toThrow();
  });

  const invalidConfigs: Array<[unknown, string]> = [
    [{ accessToken: { key: new Uint8Array(8) } }, "short key"],
    [{ accessToken: { key, expiresInSeconds: 0 } }, "bad expiry"],
    [{ accessToken: { key, algorithm: "none" } }, "bad algorithm"],
    [{ password: { workFactor: 32 }, accessToken: { key } }, "bad work factor"],
    [
      { mode: "production", accessToken: { key } },
      "production issuer and audience",
    ],
    [
      {
        mode: "production",
        accessToken: {
          key,
          issuer: "service",
          audience: "api",
          expiresInSeconds: 3601,
        },
      },
      "production token lifetime",
    ],
  ];

  it.each(invalidConfigs)("rejects invalid configuration: %s", (config) => {
    expect(() => createAuth(config as AuthConfig)).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
    );
  });
});
