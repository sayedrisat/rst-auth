# Password utilities

The package uses `bcryptjs`; it does not silently switch to another password hash. `auth.password.hash(password)` and `verify(password, hash)` validate inputs. Bcrypt only uses 72 input bytes, so this API rejects longer UTF-8 password inputs rather than allowing truncation. Malformed hashes fail safely.

```ts
const hash = await auth.password.hash(password);
const valid = await auth.password.verify(password, hash);
```

Do not return or log hashes. When a login identifier has no matching user, `verifyDummy(password)` compares against a process-local dummy hash so the unknown-user path does password-hash work too:

```ts
const user = await users.findByEmail(email);
if (!user) {
  await auth.password.verifyDummy(password);
  throw new AuthError("UNAUTHORIZED", "Invalid email or password");
}
if (!(await auth.password.verify(password, user.passwordHash))) {
  throw new AuthError("UNAUTHORIZED", "Invalid email or password");
}
```

This helps reduce timing differences; it is not a rate limiter and does not guarantee identical response timing. The default work factor is 12. Higher factors increase offline-guessing cost and CPU time for each operation, including synchronous dummy-hash setup in `createAuth()`. Benchmark a value on production-like hardware and tune capacity controls in the application.
