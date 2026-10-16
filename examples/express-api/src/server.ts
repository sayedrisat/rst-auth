import { createExampleApp } from "./app.js";

const secret = process.env.ACCESS_TOKEN_SECRET;
if (!secret) {
  throw new Error(
    "Set ACCESS_TOKEN_SECRET to a random value of at least 32 bytes",
  );
}

const { app } = createExampleApp({ accessTokenSecret: secret });
const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  process.stdout.write(`Example API listening on port ${port}\n`);
});
