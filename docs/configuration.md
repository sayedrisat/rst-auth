# Configuration

`createAuth(config)` validates config once and throws `AuthError` with code `INVALID_CONFIGURATION` for invalid settings. Configuration is injected; do not pass secrets per operation or derive algorithms from untrusted token headers.

```ts
const auth = createAuth({
  mode: "production",
  password: { workFactor: 12 },
  accessToken: {
    key: hmacKey,
    algorithm: "HS256",
    algorithms: ["HS256"],
    issuer: "billing-api",
    audience: ["billing-web", "billing-worker"],
    expiresInSeconds: 900,
    requiredClaims: ["tenant"],
  },
  refreshToken: {
    store: refreshTokenStore,
    refreshTokenTtl: 60 * 60 * 24 * 7,
    absoluteLifetime: 60 * 60 * 24 * 30,
  },
});
```

HMAC keys are `Uint8Array` values of at least 32 bytes. Asymmetric algorithms require a JOSE `CryptoKey` or Node `KeyObject`. `algorithm` chooses signing; `algorithms` is the pinned verification allowlist and must include the signing algorithm. An optional `keyResolver(header)` supports key lookup by `kid` while the allowlist remains configured. Production mode requires issuer and audience and limits access expiry to one hour.

The default bcrypt work factor is 12 and the default access-token expiry is 900 seconds. Work factor must be an integer from 4 to 31. Refresh support is disabled when `refreshToken` is omitted; enabling it requires a store, idle TTL, and absolute family lifetime, each a positive safe integer in seconds.

`isRevoked(claims, context?)` can check application state during verification. Express passes the current request as `context`; direct calls can pass a context themselves. The hook makes verification stateful and adds its latency and availability to protected requests.
