import { createHash, randomBytes, randomUUID } from "node:crypto";
import { AuthError } from "./errors.js";
import type { RefreshTokenStore } from "./refresh-store.js";

const TOKEN_BYTES = 32;

export interface IssueRefreshTokenInput {
  subject: string;
}

export interface IssuedRefreshToken {
  refreshToken: string;
  familyId: string;
  subject: string;
  expiresAt: Date;
  absoluteExpiresAt: Date;
}

export interface RefreshTokenService {
  issue(input: IssueRefreshTokenInput): Promise<IssuedRefreshToken>;
  rotate(refreshToken: string): Promise<IssuedRefreshToken>;
  /** Revoke one active token. Repeated calls and unknown tokens are harmless. */
  revoke(refreshToken: string): Promise<void>;
  revokeFamily(familyId: string): Promise<void>;
  revokeAllForSubject(subject: string): Promise<void>;
}

export interface RefreshTokenServiceConfig {
  store: RefreshTokenStore;
  refreshTokenTtl: number;
  absoluteLifetime: number;
}

export function hashRefreshToken(token: string): string {
  return createHash("sha256").update(token, "utf8").digest("hex");
}

function opaqueToken(): string {
  return randomBytes(TOKEN_BYTES).toString("base64url");
}

function tokenExpiry(now: Date, ttlSeconds: number, absoluteExpiresAt: Date) {
  const idleExpiry = new Date(now.getTime() + ttlSeconds * 1000);
  return idleExpiry < absoluteExpiresAt
    ? idleExpiry
    : new Date(absoluteExpiresAt);
}

function invalidRefreshToken(
  status: "expired" | "revoked" | "not_found",
): never {
  throw new AuthError(
    "REFRESH_TOKEN_INVALID",
    `Refresh token cannot be used: ${status}`,
  );
}

export function createRefreshTokenService(
  config: RefreshTokenServiceConfig,
): RefreshTokenService {
  return {
    async issue({ subject }): Promise<IssuedRefreshToken> {
      if (typeof subject !== "string" || subject.length === 0) {
        throw new AuthError(
          "VALIDATION_ERROR",
          "Refresh-token subject must be a non-empty string",
        );
      }

      const now = new Date();
      const familyId = randomUUID();
      const absoluteExpiresAt = new Date(
        now.getTime() + config.absoluteLifetime * 1000,
      );
      const refreshToken = opaqueToken();
      const expiresAt = tokenExpiry(
        now,
        config.refreshTokenTtl,
        absoluteExpiresAt,
      );
      await config.store.create({
        tokenHash: hashRefreshToken(refreshToken),
        familyId,
        subject,
        createdAt: now,
        expiresAt,
        absoluteExpiresAt,
        status: "active",
      });
      return { refreshToken, familyId, subject, expiresAt, absoluteExpiresAt };
    },

    async rotate(refreshToken): Promise<IssuedRefreshToken> {
      if (typeof refreshToken !== "string" || refreshToken.length === 0) {
        invalidRefreshToken("not_found");
      }
      const now = new Date();
      const result = await config.store.consume(
        hashRefreshToken(refreshToken),
        now,
      );
      if (result.status === "reused") {
        throw new AuthError(
          "REFRESH_TOKEN_REUSED",
          "A consumed refresh token was presented again; its family was revoked",
        );
      }
      if (result.status !== "ok") invalidRefreshToken(result.status);

      const { record } = result;
      const expiresAt = tokenExpiry(
        now,
        config.refreshTokenTtl,
        record.absoluteExpiresAt,
      );
      if (expiresAt <= now) invalidRefreshToken("expired");

      const nextRefreshToken = opaqueToken();
      await config.store.create({
        tokenHash: hashRefreshToken(nextRefreshToken),
        familyId: record.familyId,
        subject: record.subject,
        createdAt: now,
        expiresAt,
        absoluteExpiresAt: record.absoluteExpiresAt,
        status: "active",
      });
      return {
        refreshToken: nextRefreshToken,
        familyId: record.familyId,
        subject: record.subject,
        expiresAt,
        absoluteExpiresAt: new Date(record.absoluteExpiresAt),
      };
    },

    async revoke(refreshToken): Promise<void> {
      if (typeof refreshToken !== "string" || refreshToken.length === 0) return;
      await config.store.revokeToken(
        hashRefreshToken(refreshToken),
        new Date(),
      );
    },

    async revokeFamily(familyId): Promise<void> {
      if (typeof familyId !== "string" || familyId.length === 0) {
        throw new AuthError(
          "VALIDATION_ERROR",
          "Refresh-token family ID must be a non-empty string",
        );
      }
      await config.store.revokeFamily(familyId, new Date());
    },

    async revokeAllForSubject(subject): Promise<void> {
      if (typeof subject !== "string" || subject.length === 0) {
        throw new AuthError(
          "VALIDATION_ERROR",
          "Refresh-token subject must be a non-empty string",
        );
      }
      await config.store.revokeAllForSubject(subject, new Date());
    },
  };
}
