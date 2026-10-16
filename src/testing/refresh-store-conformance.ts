import type {
  RefreshTokenRecord,
  RefreshTokenStore,
} from "../refresh-store.js";

export interface ConformanceTestRegistrar {
  test(name: string, fn: () => void | Promise<void>): unknown;
}

export type RefreshTokenStoreFactory = () =>
  RefreshTokenStore | Promise<RefreshTokenStore>;

const BASE_TIME = new Date("2030-01-01T00:00:00.000Z");

function record(
  tokenHash: string,
  overrides: Partial<RefreshTokenRecord> = {},
): RefreshTokenRecord {
  return {
    tokenHash,
    familyId: "family-default",
    subject: "subject-default",
    createdAt: BASE_TIME,
    expiresAt: new Date(BASE_TIME.getTime() + 60_000),
    absoluteExpiresAt: new Date(BASE_TIME.getTime() + 120_000),
    status: "active",
    ...overrides,
  };
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition)
    throw new Error(`RefreshTokenStore conformance failure: ${message}`);
}

/**
 * Registers a runner-neutral set of contract tests. Pass an adapter for your
 * test runner's `test`/`it` function and a factory that creates an empty store.
 */
export function registerRefreshTokenStoreConformanceTests(
  registrar: ConformanceTestRegistrar,
  createStore: RefreshTokenStoreFactory,
): void {
  registrar.test(
    "supports consuming a token and storing its rotated successor",
    async () => {
      const store = await createStore();
      const original = record("a".repeat(64));
      await store.create(original);
      const consumed = await store.consume(original.tokenHash, BASE_TIME);
      assert(consumed.status === "ok", "an active token must be consumed");

      const successor = record("b".repeat(64), {
        familyId: original.familyId,
        subject: original.subject,
      });
      await store.create(successor);
      const next = await store.consume(successor.tokenHash, BASE_TIME);
      assert(
        next.status === "ok",
        "the successor in the same family must be consumable",
      );
    },
  );

  registrar.test("detects replay of a consumed token", async () => {
    const store = await createStore();
    const token = record("c".repeat(64));
    await store.create(token);
    assert(
      (await store.consume(token.tokenHash, BASE_TIME)).status === "ok",
      "first consume must win",
    );
    assert(
      (await store.consume(token.tokenHash, BASE_TIME)).status === "reused",
      "a second consume must report reuse",
    );
  });

  registrar.test("revokes the entire family after reuse", async () => {
    const store = await createStore();
    const original = record("d".repeat(64), { familyId: "family-reuse" });
    const sibling = record("e".repeat(64), { familyId: "family-reuse" });
    await store.create(original);
    await store.create(sibling);
    await store.consume(original.tokenHash, BASE_TIME);
    assert(
      (await store.consume(original.tokenHash, BASE_TIME)).status === "reused",
      "replay must be detected",
    );
    assert(
      (await store.consume(sibling.tokenHash, BASE_TIME)).status === "revoked",
      "all tokens in the family must be revoked",
    );
    let refusedSuccessor = false;
    try {
      await store.create(record("6".repeat(64), { familyId: "family-reuse" }));
    } catch {
      refusedSuccessor = true;
    }
    assert(
      refusedSuccessor,
      "a revoked family must reject a late successor create",
    );
  });

  registrar.test("rejects expired tokens", async () => {
    const store = await createStore();
    const token = record("f".repeat(64), {
      expiresAt: BASE_TIME,
      absoluteExpiresAt: new Date(BASE_TIME.getTime() + 60_000),
    });
    await store.create(token);
    assert(
      (await store.consume(token.tokenHash, BASE_TIME)).status === "expired",
      "expiry is exclusive at expiresAt",
    );
  });

  registrar.test(
    "supports single-token, family, and subject revocation",
    async () => {
      const store = await createStore();
      const single = record("1".repeat(64), { familyId: "family-single" });
      const familyMember = record("2".repeat(64), { familyId: "family-all" });
      const otherFamily = record("3".repeat(64), {
        familyId: "family-other",
        subject: "subject-all",
      });
      for (const item of [single, familyMember, otherFamily])
        await store.create(item);

      await store.revokeToken(single.tokenHash, BASE_TIME);
      assert(
        (await store.consume(single.tokenHash, BASE_TIME)).status === "revoked",
        "single-token revoke must block that token",
      );
      await store.revokeFamily("family-all", BASE_TIME);
      assert(
        (await store.consume(familyMember.tokenHash, BASE_TIME)).status ===
          "revoked",
        "family revoke must block family members",
      );
      let rejectedLateFamilyMember = false;
      try {
        await store.create(record("5".repeat(64), { familyId: "family-all" }));
      } catch {
        rejectedLateFamilyMember = true;
      }
      assert(
        rejectedLateFamilyMember,
        "create must not recreate a family after revocation",
      );
      await store.revokeAllForSubject("subject-all", BASE_TIME);
      assert(
        (await store.consume(otherFamily.tokenHash, BASE_TIME)).status ===
          "revoked",
        "subject revoke must block all of that subject's tokens",
      );
    },
  );

  registrar.test("allows only one concurrent consume to win", async () => {
    const store = await createStore();
    const token = record("4".repeat(64));
    await store.create(token);
    const results = await Promise.all([
      store.consume(token.tokenHash, BASE_TIME),
      store.consume(token.tokenHash, BASE_TIME),
    ]);
    assert(
      results.filter((result) => result.status === "ok").length === 1,
      "exactly one concurrent caller must receive ok",
    );
    assert(
      results.some((result) => result.status === "reused"),
      "the losing concurrent caller must be recognized as reuse",
    );
  });
}
