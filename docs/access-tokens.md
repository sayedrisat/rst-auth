# Access tokens

Access tokens are signed with `jose`. The configured algorithm and allowlist are used; the verifier does not choose an algorithm from the incoming JWT header. Tokens carry `token_use: "access"`. Verification checks signatures, expiry, issued-at time, configured issuer/audience, required claims, subject, and token type.

```ts
const token = await auth.tokens.generateAccessToken({
  sub: user.id,
  role: user.role,
});
const claims = await auth.tokens.verifyAccessToken(token);
```

Reserved claims belong to the library and cannot be supplied as caller payload. Static keys are supported; an optional async `keyResolver(header)` can resolve keys by `kid` during rotation. It does not change the configured algorithm allowlist.

The optional `isRevoked(claims, context?)` hook lets applications consult a denylist or session state. It makes verification stateful and adds a dependency to each verification. Without such a lookup, an otherwise valid token does not prove that the user still exists or is active; roles embedded in a token can be stale. Keep token lifetimes and current-permission checks appropriate for the application. Never log full tokens.
