# RST-Auth

**Complex authentication. Simple methods. Full control. Open source.**

## Overview

`RST-Auth` is an alpha TypeScript toolkit for Node.js 22+ applications. It provides password hashing, access tokens, stateful refresh-token rotation, and optional Express and Zod adapters. Your application owns its users, database, routes, business rules, and responses.

## Problem

Authentication code is easy to get subtly wrong, while full authentication frameworks may own user models, database tables, and application flows. This package focuses on reusable security mechanics and leaves application-specific decisions with the developer.

## Features

- `bcryptjs` password hashing, 72-byte input checks, and dummy verification.
- `jose` access tokens with configured algorithms, issuer/audience checks, key resolution, and optional revocation lookup.
- Opaque refresh tokens with atomic store consumption, rotation, family revocation, and reuse detection.
- Express 4 and 5 authentication, role authorization, validation, and safe error middleware.
- Zod adapter and a framework-agnostic refresh-store conformance suite.
- Injected configuration; the library does not read `process.env`.

Feature and security claims are mapped to named tests in [docs/claims.md](docs/claims.md).

## Security philosophy

The library handles reusable primitives and validates configuration. The application decides who a user is, what a role means, where data is stored, how sessions are delivered, and which HTTP response to return. Tokens are secrets: keep them out of logs and URLs. A valid access token does not establish that its subject still exists or remains enabled, and token-carried roles may be stale.

## Install

```sh
npm install rst-auth
```

Core password, token, and refresh APIs need no framework peer. For the optional integrations, install the peers you use:

```sh
npm install express zod
npm install --save-dev @types/express
```

See [installation](docs/installation.md) for Node and package details.

## Minimal setup

Configuration belongs in your application's config layer. Never commit a real signing secret.

```ts
import { createAuth } from "rst-auth";

const secret = process.env.ACCESS_TOKEN_SECRET;
if (!secret || Buffer.byteLength(secret, "utf8") < 32) {
  throw new Error("Set ACCESS_TOKEN_SECRET to at least 32 bytes");
}

const auth = createAuth({
  accessToken: {
    key: new TextEncoder().encode(secret),
    issuer: "my-service",
    audience: "my-api",
  },
});
```

## Passwords

```ts
const passwordHash = await auth.password.hash(password);
const matches = await auth.password.verify(password, passwordHash);

// When no user exists, do a dummy comparison before returning the same login error.
if (!user) await auth.password.verifyDummy(password);
```

Passwords above 72 UTF-8 bytes are rejected because bcrypt truncates longer inputs. The default work factor is 12; benchmark it on the deployment hardware because hashing and `createAuth()` startup work increase with the setting. See [passwords](docs/passwords.md).

## Access tokens

```ts
const token = await auth.tokens.generateAccessToken({
  sub: user.id,
  role: user.role,
});
const verifiedClaims = await auth.tokens.verifyAccessToken(token);
```

The verifier uses the configured algorithm allowlist and validates signature, expiry, issuer/audience when configured, required claims, and token type. See [access tokens](docs/access-tokens.md).

## Refresh tokens

Refresh support requires a store. The built-in `MemoryRefreshTokenStore` is for tests and local demonstrations only; it is not a production persistence option.

```ts
import { createAuth, MemoryRefreshTokenStore } from "rst-auth";

const auth = createAuth({
  accessToken: { key: new TextEncoder().encode(secret) },
  refreshToken: {
    store: new MemoryRefreshTokenStore(), // Use a shared persistent store in deployed services.
    refreshTokenTtl: 60 * 60 * 24 * 7,
    absoluteLifetime: 60 * 60 * 24 * 30,
  },
});

const issued = await auth.refresh!.issue({ subject: user.id });
const next = await auth.refresh!.rotate(issued.refreshToken);
```

The application creates an access token from the returned subject and its current user/permission data. Rotation consumes a stored hash atomically; presenting a consumed token revokes its family. Read [refresh tokens](docs/refresh-tokens.md) before implementing a store.

## Express middleware

```ts
import { expressAuth } from "rst-auth/express";

const middleware = expressAuth(auth);
app.get("/profile", middleware.authenticate(), profileController);
app.delete(
  "/admin/users/:id",
  middleware.authenticate(),
  middleware.authorize({ roles: ["admin"] }),
  deleteUserController,
);
```

Authentication defaults to strict `Authorization: Bearer` parsing. Optional auth is available with `authenticate({ required: false })`; a present invalid token still fails. See [middleware](docs/middleware.md).

## Validation

```ts
import { expressAuth } from "rst-auth/express";
import { zodAdapter } from "rst-auth/zod";

const middleware = expressAuth(auth, { validator: zodAdapter() });
app.post(
  "/items",
  middleware.validate({ body: itemSchema }),
  createItemController,
);
```

Parsed values are placed on `req.validated`; `req.body`, `req.params`, and `req.query` are not silently replaced. See [validation](docs/validation.md).

## Errors

`AuthError` exposes a stable code, developer message, safe public message, status, and optional cause. The Express error handler emits only safe fields by default; an application may provide a formatter. See [error handling](docs/error-handling.md).

## Configuration reference

| Setting                            | Purpose                        | Default / constraint                                                                 |
| ---------------------------------- | ------------------------------ | ------------------------------------------------------------------------------------ |
| `mode`                             | Runtime validation profile     | `development`; `production` requires issuer and audience and access expiry <= 1 hour |
| `password.workFactor`              | bcrypt cost                    | `12`, integer 4–31                                                                   |
| `accessToken.key`                  | Signing key                    | Required; HMAC keys need at least 32 bytes                                           |
| `accessToken.algorithm`            | Signing algorithm              | `HS256`; supported JOSE algorithms are explicitly listed in config types             |
| `accessToken.algorithms`           | Verification allowlist         | Signing algorithm by default; must contain it                                        |
| `accessToken.issuer`, `audience`   | JWT issuer/audience checks     | Optional outside production                                                          |
| `accessToken.expiresInSeconds`     | Access-token lifetime          | `900` seconds                                                                        |
| `accessToken.keyId`, `keyResolver` | Key rotation support           | Optional; resolver requires a `kid`                                                  |
| `accessToken.requiredClaims`       | Additional required JWT claims | `sub`, `iat`, and `exp` are required automatically                                   |
| `accessToken.isRevoked`            | Stateful verification check    | Optional; callback latency/availability is part of each verification                 |
| `refreshToken.store`               | Atomic refresh-token state     | Omit to disable refresh support                                                      |
| `refreshToken.refreshTokenTtl`     | Idle refresh expiry            | Required when refresh is enabled, in seconds                                         |
| `refreshToken.absoluteLifetime`    | Family lifetime cap            | Required when refresh is enabled, in seconds                                         |

See [configuration](docs/configuration.md) for validation details and asymmetric-key examples.

## TypeScript

The package ships declarations and strict public types. `req.auth` and `req.validated` are augmented when the Express subpath is imported. For schema-specific parsed values, use the exported `ValidatedRequest<TSchemas>` type. Install `@types/express` when using the Express integration.

## Database integration model

The toolkit does not create a user table or issue database queries. Your repository/controller code stores password hashes and looks up users. Refresh support uses the `RefreshTokenStore` interface; implement it with your own persistence and atomic compare-and-swap operation, then run the `rst-auth/testing` conformance suite against it. See [installation](docs/installation.md#database-integration-model) and [refresh tokens](docs/refresh-tokens.md).

## Limitations

This is alpha software, not a security audit or a complete identity system. It does not provide a production refresh store, user/session database, OAuth, MFA, account lockout, password reset, email verification, CORS policy, rate limiting, or CSRF protection. The memory refresh store is process-local. A token's roles can be stale unless the app performs current identity/permission checks. See [security](docs/security.md).

## Testing

```sh
npm ci
npm run build
npm test
npm run lint
npm run typecheck
npm run format:check
npm pack --dry-run
npm run example:install
npm --prefix examples/express-api run typecheck
npm --prefix examples/express-api test
npm --prefix examples/express-api run import-check
```

The example installer creates a package tarball and installs that tarball into the example; it does not import source files from this repository. CI checks Node 22 and 24.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md), keep every documented security/feature claim connected to a test, and run all quality gates before proposing changes. The project follows the [Code of Conduct](CODE_OF_CONDUCT.md). Report vulnerabilities using [SECURITY.md](SECURITY.md), not a public issue.

## License

MIT; Copyright (c) 2026 Sayed Risat. See [LICENSE](LICENSE).

## Project status

Version `0.1.0` is an alpha under active development. Public API names, policies, and docs may change before a stable release. No production-readiness claim is made.

## Comparison

This is a README-level comparison based on this project's checked-in competitive review, not an independent source audit. The reviewed JWT utility examples generally describe issuing new stateless JWTs on refresh without documented stored-token reuse detection; this package instead requires server-side refresh state and atomic consume for rotation. Broader authentication frameworks may manage schemas and migrations; this package leaves database schema and queries to the application. `express-jwt` focuses on middleware rather than passwords, refresh rotation, or validation. The reviewed analysis did not verify every package in the market, so these points describe only that review's scope and are not universal claims.
