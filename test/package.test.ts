import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

const manifest = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as {
  type: string;
  engines: { node: string };
  exports: Record<string, { types: string; import: string }>;
};

describe("published package metadata", () => {
  it("declares ESM, Node 22+, and built targets for every documented subpath", () => {
    expect(manifest.type).toBe("module");
    expect(manifest.engines.node).toBe(">=22");
    expect(Object.keys(manifest.exports).sort()).toEqual([
      ".",
      "./express",
      "./testing",
      "./zod",
    ]);
    for (const entry of Object.values(manifest.exports)) {
      expect(entry.import).toMatch(/^\.\/dist\/.*\.js$/);
      expect(entry.types).toMatch(/^\.\/dist\/.*\.d\.ts$/);
    }
  });

  it("keeps environment reads out of the injected core configuration layer", () => {
    const collectFiles = (directory: string): string[] =>
      readdirSync(directory).flatMap((entry) => {
        const path = join(directory, entry);
        return statSync(path).isDirectory() ? collectFiles(path) : [path];
      });
    for (const file of collectFiles(
      fileURLToPath(new URL("../src/", import.meta.url)),
    )) {
      expect(readFileSync(file, "utf8"), file).not.toMatch(/\bprocess\.env\b/);
    }
  });
});
