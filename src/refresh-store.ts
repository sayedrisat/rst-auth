export type RefreshTokenStatus = "active" | "consumed" | "revoked";

export interface RefreshTokenRecord {
  /** A SHA-256 digest of the opaque token. Raw refresh tokens must never be stored. */
  tokenHash: string;
  familyId: string;
  subject: string;
  createdAt: Date;
  expiresAt: Date;
  absoluteExpiresAt: Date;
  status: RefreshTokenStatus;
  consumedAt?: Date;
}

export type ConsumeResult =
  | { status: "ok"; record: RefreshTokenRecord }
  | { status: "not_found" }
  | { status: "expired" }
  | { status: "revoked" }
  | { status: "reused" };

export type RevokeTokenResult =
  { status: "revoked" } | { status: "not_found" } | { status: "inactive" };

/**
 * Implementations must make consume a single atomic compare-and-swap operation.
 * A store that cannot ensure only one concurrent caller gets `ok` cannot claim
 * refresh-token reuse protection. Re-presenting a consumed token must revoke
 * its family before returning `reused`. Stores must retain family-revocation
 * tombstones through the family absolute expiry so a late rotation cannot
 * recreate a revoked family.
 */
export interface RefreshTokenStore {
  /** Must reject records for a family that has already been revoked. */
  create(record: RefreshTokenRecord): Promise<void>;
  consume(tokenHash: string, now: Date): Promise<ConsumeResult>;
  revokeToken(tokenHash: string, now: Date): Promise<RevokeTokenResult>;
  revokeFamily(familyId: string, now: Date): Promise<void>;
  revokeAllForSubject(subject: string, now: Date): Promise<void>;
}
