# Security responsibilities

This package supplies auth primitives; it does not replace application security controls or an independent security review. Keep dependencies current, protect signing keys, avoid logging credentials/tokens/hashes, validate inputs, and review the threat model of the deployed refresh store.

The application remains responsible for:

- **CORS:** allow only required origins and methods. CORS is not authentication and is not a CSRF defense by itself.
- **Rate limiting:** limit login, signup, refresh, password reset, and other sensitive endpoints by appropriate identifiers and network context.
- **CSRF:** browser cookies are attached automatically in some cross-site contexts. Use CSRF defenses appropriate to the routes and cookie policy; SameSite helps but is not a universal replacement. See [cookies versus Bearer](cookies-vs-bearer.md).
- **Account lockout and abuse policy:** define throttling, lockout, recovery, and monitoring without creating trivial denial-of-service paths.
- **Password reset:** design single-use, expiring, securely stored reset credentials and account notification yourself.
- **Email verification, account status, user lookup, and current permissions:** a signed token alone does not show that an account remains active or current.
- **Signing key lifecycle, backup, rotation, and deployment secret access.**
- **Refresh persistence:** provide a shared store whose consume and family revocation operations are atomic for your database/consistency model. Memory store is test/local only.

`isRevoked` can provide access-token denylist/session checks, at the cost of making verification stateful and dependent on that check. A valid JWT without current lookup may outlive a deleted or disabled user until its expiry. Choose access-token lifetime and current authorization checks accordingly.
