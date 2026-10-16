import type {
  ConsumeResult,
  RefreshTokenRecord,
  RefreshTokenStore,
  RevokeTokenResult,
} from "./refresh-store.js";

function copyRecord(record: RefreshTokenRecord): RefreshTokenRecord {
  return {
    ...record,
    createdAt: new Date(record.createdAt),
    expiresAt: new Date(record.expiresAt),
    absoluteExpiresAt: new Date(record.absoluteExpiresAt),
    ...(record.consumedAt === undefined
      ? {}
      : { consumedAt: new Date(record.consumedAt) }),
  };
}

/**
 * In-memory store for tests and local examples only. It is not safe across
 * processes, restarts, or multiple application instances.
 */
export class MemoryRefreshTokenStore implements RefreshTokenStore {
  private readonly records = new Map<string, RefreshTokenRecord>();
  private readonly revokedFamilies = new Set<string>();

  async create(record: RefreshTokenRecord): Promise<void> {
    if (this.revokedFamilies.has(record.familyId)) {
      throw new Error("Cannot create a refresh token in a revoked family");
    }
    if (this.records.has(record.tokenHash)) {
      throw new Error("Refresh token hash already exists");
    }
    this.records.set(record.tokenHash, copyRecord(record));
  }

  async consume(tokenHash: string, now: Date): Promise<ConsumeResult> {
    // This mutation happens before the async method yields, giving this
    // single-process implementation compare-and-swap behavior.
    const record = this.records.get(tokenHash);
    if (!record) return { status: "not_found" };
    if (record.status === "revoked") return { status: "revoked" };
    if (record.status === "consumed") {
      await this.revokeFamily(record.familyId, now);
      return { status: "reused" };
    }
    if (now >= record.expiresAt || now >= record.absoluteExpiresAt) {
      return { status: "expired" };
    }

    record.status = "consumed";
    record.consumedAt = new Date(now);
    return { status: "ok", record: copyRecord(record) };
  }

  async revokeToken(tokenHash: string, _now: Date): Promise<RevokeTokenResult> {
    void _now;
    const record = this.records.get(tokenHash);
    if (!record) return { status: "not_found" };
    if (record.status !== "active") return { status: "inactive" };
    record.status = "revoked";
    return { status: "revoked" };
  }

  async revokeFamily(familyId: string, _now: Date): Promise<void> {
    void _now;
    this.revokedFamilies.add(familyId);
    for (const record of this.records.values()) {
      if (record.familyId === familyId) record.status = "revoked";
    }
  }

  async revokeAllForSubject(subject: string, _now: Date): Promise<void> {
    void _now;
    for (const record of this.records.values()) {
      if (record.subject === subject) {
        this.revokedFamilies.add(record.familyId);
        record.status = "revoked";
      }
    }
  }
}
