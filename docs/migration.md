# Migration notes

## From stateless refresh JWTs

Stateless re-issuance does not invalidate the presented token. To use this package's rotation and reuse detection, configure a persistent `RefreshTokenStore` with atomic consume before enabling refresh support. Existing JWT refresh credentials cannot be imported as active opaque-token families. Plan a session cutover: require users to authenticate again or maintain a separately designed transition window, then remove old verification after it expires. Do not label stateless re-issuance as rotation.

## From application-owned access JWTs

Map the current subject and authorization data into `generateAccessToken` claims while respecting reserved names. Configure issuer, audience, lifetime, and a pinned algorithm allowlist to match intended consumers. Review key format and key rotation before switching. The library uses `token_use: "access"`; old tokens without that claim will not verify as access tokens.

## From another password-hash format

This version supports bcryptjs only. Keep existing verification in your application during a staged migration if needed, then rehash after a successful verification. Do not downgrade a hash or silently accept bcrypt inputs above its 72-byte boundary. Plan password resets where a safe migration is not possible.

## HTTP middleware

The default source is strict `Authorization: Bearer`. If the old app used cookies or another source, configure `getToken` explicitly and add CSRF protection when using browser cookies. Validation now returns parsed data through `req.validated`; update controllers to read that property rather than expecting request fields to be replaced.
