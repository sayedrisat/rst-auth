# Installation and integration model

## Requirements and package entries

The package targets Node.js 22 and newer and ships ESM JavaScript plus TypeScript declarations. Install the core package with `npm install rst-auth`. Core imports are `rst-auth` and `rst-auth/testing`.

Express and Zod are optional peers, isolated behind `rst-auth/express` and `rst-auth/zod`:

```sh
npm install rst-auth express zod
npm install --save-dev @types/express
```

Express 4 and 5 are supported by the adapter. The application should use a compatible `@types/express` version when typechecking Express routes.

## Minimal app setup

```ts
import { createAuth } from "rst-auth";
import { expressAuth } from "rst-auth/express";
import { zodAdapter } from "rst-auth/zod";

const auth = createAuth({
  accessToken: {
    key: new TextEncoder().encode(config.accessTokenSecret),
    issuer: "service-name",
    audience: "service-api",
  },
});
const middleware = expressAuth(auth, { validator: zodAdapter() });
```

Read secrets in the application's configuration layer and pass them into `createAuth`; the library itself does not read environment variables.

## Database integration model

The application owns user records, unique email constraints, queries, transactions, and user status rules. The package accepts a `RefreshTokenStore` when refresh support is enabled. Production implementations should store token hashes and make consume/revocation operations atomic and shared across application instances. The example app uses an in-memory user repository and refresh store only to demonstrate the controller boundaries; neither is suitable for deployed state.

Use `rst-auth/testing` to register the refresh-store conformance suite with your test runner. A passing suite does not replace reviewing the backend's transactional and consistency guarantees.
