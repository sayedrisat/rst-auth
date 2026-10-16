import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createExampleApp, type ExampleApp } from "../src/app.js";
import { InMemoryUserRepository } from "../src/user-repository.js";

const secret = "example-test-secret-is-at-least-32-bytes";

describe("example Express API", () => {
  let example: ExampleApp;

  beforeEach(() => {
    example = createExampleApp({
      accessTokenSecret: secret,
      repository: new InMemoryUserRepository(),
    });
  });

  it("no-role-from-client: rejects a client role and creates no account", async () => {
    const response = await request(example.app)
      .post("/auth/signup")
      .send({ email: "attacker@example.test", password: "pw", role: "admin" });
    expect(response.status).toBe(400);
    expect(example.repository.size).toBe(0);
    expect(JSON.stringify(response.body)).not.toContain("admin");
  });

  it("uses application-owned controllers, hashing, and repository roles", async () => {
    const signup = await request(example.app)
      .post("/auth/signup")
      .send({ email: "user@example.test", password: "long enough passphrase" });
    expect(signup.status).toBe(200);
    expect(signup.body.user.role).toBe("user");
    expect(signup.body.user.passwordHash).toBeUndefined();
    expect(signup.body.accessToken).toBeTypeOf("string");
    expect(signup.body.refreshToken).toBeTypeOf("string");

    const me = await request(example.app)
      .get("/me")
      .set("Authorization", `Bearer ${signup.body.accessToken}`);
    expect(me.status).toBe(200);
    expect(me.body.subject).toBe(signup.body.user.id);

    const denied = await request(example.app)
      .get("/admin")
      .set("Authorization", `Bearer ${signup.body.accessToken}`);
    expect(denied.status).toBe(403);

    const rotated = await request(example.app)
      .post("/auth/refresh")
      .send({ refreshToken: signup.body.refreshToken });
    expect(rotated.status).toBe(200);
    expect(rotated.body.refreshToken).not.toBe(signup.body.refreshToken);
  });

  it("supports cookie delivery with secure defaults and hides unexpected errors", async () => {
    const passwordHash = await example.auth.password.hash("admin password");
    await example.repository.create(
      "admin@example.test",
      passwordHash,
      "admin",
    );
    const login = await request(example.app)
      .post("/auth/login/cookie")
      .send({ email: "admin@example.test", password: "admin password" });
    expect(login.status).toBe(200);
    expect(login.body.refreshToken).toBeUndefined();
    expect(login.headers["set-cookie"]?.[0]).toContain("HttpOnly");
    expect(login.headers["set-cookie"]?.[0]).toContain("Secure");
    expect(login.headers["set-cookie"]?.[0]).toContain("SameSite=Lax");

    const admin = await request(example.app)
      .get("/admin")
      .set("Authorization", `Bearer ${login.body.accessToken}`);
    expect(admin.status).toBe(200);
  });

  it("maps login failures without returning password hashes or secrets", async () => {
    const response = await request(example.app)
      .post("/auth/login")
      .send({ email: "missing@example.test", password: "secret password" });
    expect(response.status).toBe(401);
    const body = JSON.stringify(response.body);
    expect(body).not.toContain("secret password");
    expect(body).not.toContain(secret);
  });
});
