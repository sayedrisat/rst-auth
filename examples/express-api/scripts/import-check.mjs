import { stdout } from "node:process";

const modules = [
  "rst-auth",
  "rst-auth/express",
  "rst-auth/zod",
  "rst-auth/testing",
];

for (const specifier of modules) {
  await import(specifier);
  stdout.write(`Imported ${specifier}\n`);
}
