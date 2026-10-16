import { execFileSync } from "node:child_process";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, resolve } from "node:path";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const example = resolve(root, "examples/express-api");
const { name, version } = JSON.parse(
  readFileSync(resolve(root, "package.json"), "utf8"),
);
const tarball = `${name.replaceAll("/", "-")}-${version}.tgz`;
const examplePackagePath = resolve(example, "package.json");
const examplePackage = JSON.parse(readFileSync(examplePackagePath, "utf8"));
examplePackage.dependencies[name] = `file:./${tarball}`;
writeFileSync(
  examplePackagePath,
  `${JSON.stringify(examplePackage, null, 2)}\n`,
);

execFileSync("npm", ["pack", "--pack-destination", example], {
  cwd: root,
  stdio: "inherit",
});
execFileSync("npm", ["install", `./${tarball}`], {
  cwd: example,
  stdio: "inherit",
});
