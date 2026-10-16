import { describe, expect, it } from "vitest";
import { createAuth } from "../src/index.js";

const key = new TextEncoder().encode("0123456789abcdef0123456789abcdef");

describe("password service", () => {
  const auth = createAuth({
    accessToken: { key },
    password: { workFactor: 4 },
  });

  it("hashes and verifies passwords", async () => {
    const hash = await auth.password.hash("correct horse battery staple");
    expect(hash).not.toBe("correct horse battery staple");
    expect(
      await auth.password.verify("correct horse battery staple", hash),
    ).toBe(true);
    expect(await auth.password.verify("wrong", hash)).toBe(false);
  });

  it("uses the configured bcrypt work factor and defaults to 12", async () => {
    const configuredHash = await auth.password.hash("configured-cost");
    expect(configuredHash.split("$")[2]).toBe("04");

    const defaultAuth = createAuth({ accessToken: { key } });
    const defaultHash = await defaultAuth.password.hash("default-cost");
    expect(defaultHash.split("$")[2]).toBe("12");
  });

  it("rejects empty and over-72-byte passwords by UTF-8 byte length", async () => {
    await expect(auth.password.hash("")).rejects.toMatchObject({
      code: "VALIDATION_ERROR",
    });
    await expect(auth.password.hash("é".repeat(37))).rejects.toMatchObject({
      code: "VALIDATION_ERROR",
    });
    await expect(auth.password.hash("é".repeat(36))).resolves.toBeTypeOf(
      "string",
    );
  });

  it("fails safely for malformed hashes and supports dummy verification", async () => {
    expect(await auth.password.verify("password", "not-a-bcrypt-hash")).toBe(
      false,
    );
    await expect(
      auth.password.verifyDummy("password"),
    ).resolves.toBeUndefined();
  });
});
