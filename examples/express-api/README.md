# Express API example

This is a small TypeScript app with an in-memory user repository, app-owned signup/login/refresh controllers, Zod schemas, and error responses. Repository queries and controller behavior are deliberately visible in `src/app.ts`; replace them with your own database code. The example rejects unknown signup fields, including `role`, and assigns the default role in repository code.

The example installs `rst-auth` from the tarball produced by `npm pack`:

```sh
cd ../..
npm ci
npm run build
npm run example:install
npm --prefix examples/express-api run typecheck
npm --prefix examples/express-api test
npm --prefix examples/express-api run import-check
```

The install script writes `rst-auth-<version>.tgz` into this directory and installs it as a package. App imports use package subpaths and never reach into the repository `src/` tree.

To start the server, supply an ephemeral random secret:

```sh
ACCESS_TOKEN_SECRET="$(openssl rand -hex 32)" npm --prefix examples/express-api run dev
```

Open [http://localhost:3000](http://localhost:3000) to use the browser demo. Sign up, call `/me` and `/admin`, rotate a refresh token, replay the old token to see family revocation, then try logout. The page keeps tokens in memory only; reloading clears its session.

Endpoints:

- `POST /auth/signup` and `POST /auth/login` return access and refresh tokens in JSON.
- `POST /auth/login/cookie` sets the refresh token in an HttpOnly cookie and returns the access token.
- `POST /auth/refresh` accepts a refresh token in JSON or the refresh cookie and rotates it.
- `POST /auth/logout` revokes a supplied token or cookie and clears the cookie.
- `GET /me` requires a valid access token; `GET /admin` additionally requires the server-assigned `admin` role.

`MemoryRefreshTokenStore` and the in-memory user repository are demonstration-only and lose state on restart. Use a shared persistent refresh store with atomic consume in a deployed app. Cookie delivery is CSRF-sensitive; explicit JSON delivery has different XSS/storage risks. See the root [cookie and Bearer guide](../../docs/cookies-vs-bearer.md).
