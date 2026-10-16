# Refresh-token architecture

Refresh tokens are opaque bearer secrets, not JWTs. `auth.refresh.issue()` creates 32 random bytes with Node's `crypto.randomBytes()` and returns their base64url encoding. The configured store receives only the SHA-256 hash, never the raw token. A database leak therefore does not directly reveal usable refresh tokens.

Refresh support is opt-in. Configure `refreshToken.store`, `refreshToken.refreshTokenTtl`, and `refreshToken.absoluteLifetime` when calling `createAuth()`. If no refresh configuration is supplied, `auth.refresh` is absent. A partial configuration or missing store fails validation; the library never pretends stateless token re-issuance is rotation.

## Rotation and lifetimes

Each issue starts a family with an absolute expiry. Rotation atomically consumes the presented token, then creates a replacement in that same family. The replacement's idle expiry is `min(now + refreshTokenTtl, family absolute expiry)`. Rotation cannot extend the family past `absoluteLifetime`.

The refresh service returns a rotated refresh token, its subject and family metadata. It does not mint an access token pair: application code can use the returned subject and its own current identity/authorization data to call `auth.tokens.generateAccessToken()`. Unknown, expired, revoked, or reused tokens raise an `AuthError` and never produce a replacement token.

Presenting a previously consumed token reports `REFRESH_TOKEN_REUSED` and revokes every token in that family. `revoke(token)` revokes one active token. `revokeFamily(familyId)` revokes a family, and `revokeAllForSubject(subject)` revokes all of that subject's refresh tokens.

## Store contract and atomicity

Implement `RefreshTokenStore` with `create`, `consume`, `revokeToken`, `revokeFamily`, and `revokeAllForSubject`. Store records contain the SHA-256 token hash, family ID, subject, timestamps, and status. `consume(hash, now)` returns a discriminated result: `ok`, `not_found`, `expired`, `revoked`, or `reused`.

`consume` must be an atomic compare-and-swap. Exactly one concurrent call for an active token may return `ok`; a later or concurrent loser must observe the consumed state, report reuse, and revoke the family. A read-then-write implementation without a transaction, conditional update, or equivalent atomic primitive cannot provide this guarantee and must not claim reuse protection. Backends must also make family and subject revocation cover all currently stored members of those scopes.

Stores must preserve revoked-family tombstones through the family's absolute expiry and make `create` refuse to add a successor to a revoked family. Otherwise a rotation already in progress could create a usable child after a concurrent replay revoked the family. Concurrent refresh attempts can therefore both fail: one detects reuse, and the other is prevented from creating a successor after family revocation.

The `rst-auth/testing` subpath exports `registerRefreshTokenStoreConformanceTests()`. Register the suite with your test runner and provide a factory for a fresh store. It checks rotation behavior, replay and family revocation, expiry, explicit revocation, and concurrent consume. The suite exercises the contract but does not prove a distributed backend's atomicity under every deployment or failure mode; review the backend's transaction/consistency guarantees as well.

## Memory store

`MemoryRefreshTokenStore` is only for tests and local examples. It provides atomic consume within one JavaScript process by changing state before its async method yields. It is not safe across processes, restarts, or multiple application instances. Use a persistent store with an atomic consume operation for deployed services.

## Example

```ts
import { createAuth, MemoryRefreshTokenStore } from "rst-auth";

const auth = createAuth({
  accessToken: { key: new TextEncoder().encode(process.env.ACCESS_TOKEN_KEY!) },
  refreshToken: {
    store: new MemoryRefreshTokenStore(), // local example only
    refreshTokenTtl: 60 * 60 * 24 * 7,
    absoluteLifetime: 60 * 60 * 24 * 30,
  },
});

const refresh = await auth.refresh!.issue({ subject: "user-123" });
const access = await auth.tokens.generateAccessToken({ sub: refresh.subject });
```

The sample reads the secret in application configuration; the library itself never reads `process.env`. A production application should inject a persistent store and keep raw refresh tokens out of logs and persistent records.
