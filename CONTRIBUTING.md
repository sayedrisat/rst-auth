# Contributing

Thanks for helping improve rst-auth. The project is alpha software and prioritizes clear security boundaries, small APIs, and honest documentation.

## Before opening a change

- Read the relevant design and security documentation in `docs/` before changing behavior.
- Keep user models, DB queries, routes, controllers, and business rules in the application layer.
- Do not add real credentials, publish packages, or push directly to the upstream default branch. Use a fork and pull request; do not claim production readiness.
- Every security or feature claim in README must map to a named test in `docs/claims.md`.
- Never accept a client-supplied privilege or role during signup.

## Development checks

Use Node 22 or 24 and npm. From the repository root run:

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

The example install command packs this project and installs the generated tarball into the example. Do not change the example to import source files from `src/`.

## Pull requests

Explain the user-visible behavior, security consequences, tests, docs, and compatibility impact. Include focused tests for bug fixes and new claims. Keep PRs small enough to review. Maintainers may request changes or decline work outside the project scope. By contributing, you agree to follow the [Code of Conduct](CODE_OF_CONDUCT.md).
