import { describe, expect, it, vi } from "vitest";
import { createAuth, MemoryRefreshTokenStore } from "../src/index.js";

const key = new TextEncoder().encode("0123456789abcdef0123456789abcdef");

function configuredAuth(
  options: { refreshTokenTtl?: number; absoluteLifetime?: number } = {},
) {
  return createAuth({
    password: { workFactor: 4 },
    accessToken: { key },
    refreshToken: {
      store: new MemoryRefreshTokenStore(),
      refreshTokenTtl: options.refreshTokenTtl ?? 60,
      absoluteLifetime: options.absoluteLifetime ?? 3600,
    },
  });
}

describe("refresh-token configuration", () => {
  it("refresh-stateless-not-rotation: refuses refresh without a configured store", () => {
    const auth = createAuth({ accessToken: { key } });
    expect(auth.refresh).toBeUndefined();
  });

  it("rejects refresh configuration without a complete store", () => {
    expect(() =>
      createAuth({
        accessToken: { key },
        refreshToken: {
          refreshTokenTtl: 60,
          absoluteLifetime: 3600,
        } as never,
      }),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });

  it("rejects invalid refresh lifetimes", () => {
    expect(() => configuredAuth({ refreshTokenTtl: 0 })).toThrowError(
      expect.objectContaining({ code: "INVALID_CONFIGURATION" }),
    );
    expect(() =>
      configuredAuth({ absoluteLifetime: Number.MAX_SAFE_INTEGER }),
    ).toThrowError(expect.objectContaining({ code: "INVALID_CONFIGURATION" }));
  });
});

describe("refresh-token service", () => {
  it("issues opaque 256-bit tokens and stores only their SHA-256 hashes", async () => {
    const store = new MemoryRefreshTokenStore();
    const create = vi.spyOn(store, "create");
    const auth = createAuth({
      accessToken: { key },
      refreshToken: {
        store,
        refreshTokenTtl: 60,
        absoluteLifetime: 3600,
      },
    });
    const issued = await auth.refresh!.issue({ subject: "user-1" });
    const stored = create.mock.calls[0]?.[0];
    expect(issued.refreshToken).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(issued.refreshToken).not.toContain(".");
    expect(stored?.tokenHash).toMatch(/^[a-f0-9]{64}$/);
    expect(stored?.tokenHash).not.toBe(issued.refreshToken);
  });

  it("documents the memory store's instance-local behavior", async () => {
    const firstInstance = configuredAuth();
    const issued = await firstInstance.refresh!.issue({ subject: "user-1" });
    const secondInstance = createAuth({
      accessToken: { key },
      refreshToken: {
        store: new MemoryRefreshTokenStore(),
        refreshTokenTtl: 60,
        absoluteLifetime: 3600,
      },
    });
    await expect(
      secondInstance.refresh!.rotate(issued.refreshToken),
    ).rejects.toMatchObject({ code: "REFRESH_TOKEN_INVALID" });
  });

  it("rotates into the same family and detects replay by revoking that family", async () => {
    const auth = configuredAuth();
    const initial = await auth.refresh!.issue({ subject: "user-1" });
    const rotated = await auth.refresh!.rotate(initial.refreshToken);
    expect(rotated.familyId).toBe(initial.familyId);
    expect(rotated.subject).toBe("user-1");
    expect(rotated.refreshToken).not.toBe(initial.refreshToken);

    await expect(
      auth.refresh!.rotate(initial.refreshToken),
    ).rejects.toMatchObject({
      code: "REFRESH_TOKEN_REUSED",
    });
    await expect(
      auth.refresh!.rotate(rotated.refreshToken),
    ).rejects.toMatchObject({
      code: "REFRESH_TOKEN_INVALID",
    });
  });

  it("does not return a rotation result when a concurrent replay revokes the family", async () => {
    const auth = configuredAuth();
    const initial = await auth.refresh!.issue({ subject: "user-1" });
    const results = await Promise.allSettled([
      auth.refresh!.rotate(initial.refreshToken),
      auth.refresh!.rotate(initial.refreshToken),
    ]);
    expect(results.every((result) => result.status === "rejected")).toBe(true);
    expect(
      results.some(
        (result) =>
          result.status === "rejected" &&
          result.reason?.code === "REFRESH_TOKEN_REUSED",
      ),
    ).toBe(true);
  });

  it("never rotates unknown, expired, or revoked values", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:00.000Z"));
    try {
      const auth = configuredAuth({ refreshTokenTtl: 2, absoluteLifetime: 20 });
      const expired = await auth.refresh!.issue({ subject: "expired-user" });
      vi.advanceTimersByTime(3000);
      await expect(
        auth.refresh!.rotate(expired.refreshToken),
      ).rejects.toMatchObject({
        code: "REFRESH_TOKEN_INVALID",
      });
      await expect(
        auth.refresh!.rotate("unknown-refresh-token"),
      ).rejects.toMatchObject({
        code: "REFRESH_TOKEN_INVALID",
      });

      vi.useRealTimers();
      const revokedAuth = configuredAuth();
      const revoked = await revokedAuth.refresh!.issue({ subject: "user-2" });
      await revokedAuth.refresh!.revoke(revoked.refreshToken);
      await expect(
        revokedAuth.refresh!.rotate(revoked.refreshToken),
      ).rejects.toMatchObject({ code: "REFRESH_TOKEN_INVALID" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("caps every rotation at the family's absolute lifetime", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:00.000Z"));
    try {
      const auth = configuredAuth({ refreshTokenTtl: 20, absoluteLifetime: 5 });
      const initial = await auth.refresh!.issue({ subject: "user-1" });
      expect(initial.expiresAt).toEqual(initial.absoluteExpiresAt);

      vi.advanceTimersByTime(4000);
      const rotated = await auth.refresh!.rotate(initial.refreshToken);
      expect(rotated.expiresAt).toEqual(initial.absoluteExpiresAt);

      vi.advanceTimersByTime(1100);
      await expect(
        auth.refresh!.rotate(rotated.refreshToken),
      ).rejects.toMatchObject({
        code: "REFRESH_TOKEN_INVALID",
      });
    } finally {
      vi.useRealTimers();
    }
  });

  it("renews idle expiry on rotation without changing the family cap", async () => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2030-01-01T00:00:00.000Z"));
    try {
      const auth = configuredAuth({ refreshTokenTtl: 5, absoluteLifetime: 20 });
      const initial = await auth.refresh!.issue({ subject: "user-1" });
      vi.advanceTimersByTime(4000);
      const rotated = await auth.refresh!.rotate(initial.refreshToken);
      expect(rotated.expiresAt.getTime() - initial.expiresAt.getTime()).toBe(
        4000,
      );
      expect(rotated.absoluteExpiresAt).toEqual(initial.absoluteExpiresAt);

      vi.advanceTimersByTime(1500);
      await expect(
        auth.refresh!.rotate(rotated.refreshToken),
      ).resolves.toMatchObject({ subject: "user-1" });
    } finally {
      vi.useRealTimers();
    }
  });

  it("supports family and subject-wide revocation", async () => {
    const auth = configuredAuth();
    const first = await auth.refresh!.issue({ subject: "user-1" });
    const second = await auth.refresh!.issue({ subject: "user-1" });
    const unrelated = await auth.refresh!.issue({ subject: "user-2" });
    await auth.refresh!.revokeFamily(first.familyId);
    await expect(
      auth.refresh!.rotate(first.refreshToken),
    ).rejects.toMatchObject({
      code: "REFRESH_TOKEN_INVALID",
    });
    await auth.refresh!.revokeAllForSubject("user-1");
    await expect(
      auth.refresh!.rotate(second.refreshToken),
    ).rejects.toMatchObject({
      code: "REFRESH_TOKEN_INVALID",
    });
    await expect(
      auth.refresh!.rotate(unrelated.refreshToken),
    ).resolves.toMatchObject({
      subject: "user-2",
    });
  });

  it("rejects an access token as refresh and a refresh token as access", async () => {
    const auth = configuredAuth();
    const issued = await auth.refresh!.issue({ subject: "user-1" });
    const accessToken = await auth.tokens.generateAccessToken({
      sub: "user-1",
    });
    await expect(auth.refresh!.rotate(accessToken)).rejects.toMatchObject({
      code: "REFRESH_TOKEN_INVALID",
    });
    await expect(
      auth.tokens.verifyAccessToken(issued.refreshToken),
    ).rejects.toMatchObject({
      code: "TOKEN_INVALID",
    });
  });
});
