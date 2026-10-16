# Before first release

- [ ] Verify the npm package name is available and intended; `package.json` now uses the selected name `rst-auth`.
- [ ] Verify the GitHub organization and repository name, default branch, and repository URLs in project metadata.
- [ ] Complete a trademark/name review for the package and project name.
- [ ] Verify the copyright attribution and year in `LICENSE` before each release.
- [ ] Review the documented security limitations, refresh-store implementation, operational controls, and vulnerability-reporting route.
- [ ] Run the final checks from the repository root and review the tarball contents for accidental files or credentials.

Manual commands to run only after those checks and maintainer approval:

```sh
npm whoami
npm view rst-auth name
git remote -v
npm ci
npm run format:check
npm run lint
npm run typecheck
npm test
npm run build
npm pack --dry-run
npm run example:install
npm --prefix examples/express-api run typecheck
npm --prefix examples/express-api test
npm --prefix examples/express-api run import-check
npm login
npm publish --access public
```

The final two commands require a deliberate maintainer release action. Do not run them as part of routine validation.
