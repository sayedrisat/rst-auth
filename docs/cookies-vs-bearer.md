# Refresh-token delivery: cookies and explicit requests

Refresh tokens are opaque bearer secrets. Keep them out of logs and URLs. Choose a delivery mode based on the client and threat model; the toolkit does not decide the response shape for your application.

## HttpOnly cookie

The Express helper defaults to HttpOnly, Secure, SameSite=Lax and path `/auth/refresh`:

```ts
import { setRefreshTokenCookie, fromCookie } from "rst-auth/express";

app.post("/login", async (req, res, next) => {
  try {
    const user = await users.findByEmail(req.body.email);
    const refresh = await auth.refresh!.issue({ subject: user.id });
    const accessToken = await auth.tokens.generateAccessToken({
      sub: user.id,
      role: user.role,
    });
    setRefreshTokenCookie(res, refresh.refreshToken);
    res.json({ accessToken });
  } catch (error) {
    next(error);
  }
});

app.post("/auth/refresh", async (req, res, next) => {
  try {
    const oldToken = await fromCookie("refreshToken")(req);
    const rotated = await auth.refresh!.rotate(oldToken ?? "");
    const user = await users.findById(rotated.subject);
    const accessToken = await auth.tokens.generateAccessToken({
      sub: user.id,
      role: user.role,
    });
    setRefreshTokenCookie(res, rotated.refreshToken);
    res.json({ accessToken });
  } catch (error) {
    next(error);
  }
});
```

The helper writes and clears cookies; it does not parse them. Cookie delivery lets the browser attach the refresh secret automatically, which creates CSRF risk. SameSite=Lax helps with common cross-site requests but is not a universal CSRF defense. `SameSite=None` requires Secure and an explicit CSRF defense. Restrict cookie path and domain to the smallest useful scope.

## Authorization header or request body

For clients that can manage the token explicitly, your controller can return the refresh token in a response and require it in a request body or dedicated header:

```ts
app.post("/login", async (req, res, next) => {
  try {
    const user = await users.findByEmail(req.body.email);
    const refresh = await auth.refresh!.issue({ subject: user.id });
    const accessToken = await auth.tokens.generateAccessToken({
      sub: user.id,
      role: user.role,
    });
    res.json({ accessToken, refreshToken: refresh.refreshToken });
  } catch (error) {
    next(error);
  }
});

app.post("/auth/refresh/body", async (req, res, next) => {
  try {
    const rotated = await auth.refresh!.rotate(req.body.refreshToken);
    const user = await users.findById(rotated.subject);
    const accessToken = await auth.tokens.generateAccessToken({
      sub: user.id,
      role: user.role,
    });
    res.json({ accessToken, refreshToken: rotated.refreshToken });
  } catch (error) {
    next(error);
  }
});
```

Explicit delivery avoids the browser automatically attaching the secret cross-site, reducing classic CSRF exposure. JavaScript-readable storage can increase exposure to cross-site scripting. Never put tokens in query strings: URLs are commonly copied, logged, cached, and included in referrers.

These are controller sketches. Add application-specific authentication, schema validation, CSRF defense, CORS, rate limiting, user lookup, and response policy. On Express 4, forward async controller rejections to `next(error)` as shown; the middleware only forwards its own async errors.
