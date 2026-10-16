import { describe, expect, it, vi } from "vitest";
import { generateKeyPair, SignJWT } from "jose";
import { createAuth } from "../src/index.js";

const key = new TextEncoder().encode("0123456789abcdef0123456789abcdef");

describe("access tokens", () => {
  it("generates and verifies signed tokens with configured claims", async () => {
    const auth = createAuth({
      accessToken: {
        key,
        issuer: "rst-auth-test",
        audience: "test-api",
        requiredClaims: ["sub", "role"],
      },
    });
    const token = await auth.tokens.generateAccessToken({
      sub: "user-1",
      role: "admin",
    });
    await expect(auth.tokens.verifyAccessToken(token)).resolves.toMatchObject({
      sub: "user-1",
      role: "admin",
      iss: "rst-auth-test",
      aud: "test-api",
      token_use: "access",
    });
  });

  it("pins the allowed algorithm and rejects none or header-selected alternatives", async () => {
    const auth = createAuth({ accessToken: { key, algorithm: "HS256" } });
    const good = await auth.tokens.generateAccessToken({ sub: "user-1" });
    const [header, payload, signature] = good.split(".");
    const mismatched = `${Buffer.from(JSON.stringify({ alg: "HS384", typ: "JWT" })).toString("base64url")}.${payload}.${signature}`;
    const none = `${Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url")}.${payload}.`;
    const validAlternative = await new SignJWT({ token_use: "access" })
      .setProtectedHeader({ alg: "HS384", typ: "JWT" })
      .setSubject("user-1")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(key);
    await expect(
      auth.tokens.verifyAccessToken(mismatched),
    ).rejects.toMatchObject({ code: "TOKEN_INVALID" });
    await expect(
      auth.tokens.verifyAccessToken(validAlternative),
    ).rejects.toMatchObject({ code: "TOKEN_INVALID" });
    await expect(auth.tokens.verifyAccessToken(none)).rejects.toMatchObject({
      code: "TOKEN_INVALID",
    });
    expect(header).toBeTruthy();
  });

  it("rejects caller overrides of reserved claims", async () => {
    const auth = createAuth({ accessToken: { key } });
    await expect(
      auth.tokens.generateAccessToken({ sub: "user-1", exp: 1 }),
    ).rejects.toMatchObject({ code: "VALIDATION_ERROR" });
  });

  it("requires exp and iat on verified tokens", async () => {
    const auth = createAuth({ accessToken: { key } });
    const withoutExpiry = await new SignJWT({ token_use: "access" })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setSubject("user-1")
      .setIssuedAt()
      .sign(key);
    await expect(
      auth.tokens.verifyAccessToken(withoutExpiry),
    ).rejects.toMatchObject({
      code: "TOKEN_INVALID",
    });
  });

  it("rejects token-type confusion", async () => {
    const auth = createAuth({ accessToken: { key } });
    const refreshShaped = await new SignJWT({ token_use: "refresh" })
      .setProtectedHeader({ alg: "HS256", typ: "JWT" })
      .setSubject("user-1")
      .setIssuedAt()
      .setExpirationTime("5m")
      .sign(key);
    await expect(
      auth.tokens.verifyAccessToken(refreshShaped),
    ).rejects.toMatchObject({ code: "TOKEN_INVALID" });
  });

  it("uses fake time to enforce expiry", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-01T00:00:00.000Z"));
    try {
      const auth = createAuth({ accessToken: { key, expiresInSeconds: 2 } });
      const token = await auth.tokens.generateAccessToken({ sub: "user-1" });
      vi.setSystemTime(new Date("2026-01-01T00:00:03.000Z"));
      await expect(auth.tokens.verifyAccessToken(token)).rejects.toMatchObject({
        code: "TOKEN_EXPIRED",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("resolves verification keys asynchronously by kid and supports revocation hooks", async () => {
    const resolver = vi.fn(async (header: { kid?: string }) => {
      expect(header.kid).toBe("rotation-key");
      return key;
    });
    const auth = createAuth({
      accessToken: {
        key,
        keyId: "rotation-key",
        keyResolver: resolver,
        isRevoked: async (claims) => claims.sub === "blocked-user",
      },
    });
    const token = await auth.tokens.generateAccessToken({
      sub: "blocked-user",
    });
    await expect(auth.tokens.verifyAccessToken(token)).rejects.toMatchObject({
      code: "SESSION_REVOKED",
    });
    expect(resolver).toHaveBeenCalledOnce();
  });

  it("supports asymmetric signing and verification keys", async () => {
    const { privateKey, publicKey } = await generateKeyPair("RS256");
    const auth = createAuth({
      accessToken: {
        algorithm: "RS256",
        key: privateKey,
        keyId: "rsa-1",
        keyResolver: async (header) => {
          expect(header.kid).toBe("rsa-1");
          return publicKey;
        },
      },
    });
    const token = await auth.tokens.generateAccessToken({ sub: "rsa-user" });
    await expect(auth.tokens.verifyAccessToken(token)).resolves.toMatchObject({
      sub: "rsa-user",
    });
  });
});
