# Express middleware

Install the Express peer and import the adapter subpath:

```ts
import { expressAuth, fromAny, fromCookie, fromHeader } from "rst-auth/express";

const middleware = expressAuth(auth);
app.get("/me", middleware.authenticate(), meController);
app.delete(
  "/users/:id",
  middleware.authenticate(),
  middleware.authorize({ roles: ["admin"] }),
  deleteUserController,
);
```

The default extractor strictly parses `Authorization: Bearer <token>`. `getToken` can be a synchronous or asynchronous extractor; helpers include `fromHeader()`, `fromCookie(name)`, and `fromAny([...])`. There is intentionally no built-in query-string extractor because URLs often enter logs, browser history, and referrers.

`authenticate({ required: false })` continues without `req.auth` when no token is present. A present malformed, invalid, expired, or revoked token still fails with 401. `authorize({ roles })` returns 401 when there is no authenticated request and 403 when role data is missing or does not match. Role claims can be stale; the optional `lookupIdentity(claims, req)` hook can load current app-specific identity data. No user lookup happens automatically.

`isRevoked` receives the Express request as its context when verification goes through this middleware. The adapter catches its own asynchronous failures on Express 4 and 5. Application controllers remain responsible for their own async error forwarding (Express 4 does not forward returned rejected promises automatically).

There is no `onExpired` grace hook. Letting an expired access token through during a grace window weakens the configured expiry boundary; clients should refresh through the application's refresh flow instead.
