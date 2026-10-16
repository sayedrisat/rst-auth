import { createRequire } from "node:module";
import express from "express";
import request from "supertest";
import { z } from "zod";
import { SignJWT } from "jose";
import { describe, expect, it } from "vitest";
import { createAuth } from "../src/index.js";
import { AuthError } from "../src/errors.js";
import {
  createExpressAuth,
  fromAny,
  fromCookie,
  fromHeader,
  setRefreshTokenCookie,
} from "../src/express/index.js";
import { zodAdapter } from "../src/zod/index.js";

const require = createRequire(import.meta.url);
const express4 = require("express4") as typeof express;
const express5 = express;
const key = new TextEncoder().encode("integration-test-signing-secret-32bytes");
const testVersions = [
  ["Express 4", express4],
  ["Express 5", express5],
] as const;

function makeAuth(
  isRevoked?: (
    claims: Readonly<Record<string, unknown>>,
    context?: unknown,
  ) => boolean,
) {
  return createAuth({
    password: { workFactor: 4 },
    accessToken: {
      key,
      issuer: "integration-tests",
      audience: "api",
      ...(isRevoked === undefined ? {} : { isRevoked }),
    },
  });
}

describe.each(testVersions)(
  "Express middleware on %s",
  (_label, expressImpl) => {
    it("distinguishes missing and malformed bearer headers and rejects invalid or expired tokens", async () => {
      const auth = makeAuth();
      const middleware = createExpressAuth(auth);
      const app = expressImpl();
      app.get("/private", middleware.authenticate(), (_req, res) =>
        res.sendStatus(204),
      );
      app.use(middleware.errorHandler());

      const missing = await request(app).get("/private");
      expect(missing.status).toBe(401);
      expect(missing.body.error.code).toBe("TOKEN_MISSING");
      const malformed = await request(app)
        .get("/private")
        .set("Authorization", "Basic abc");
      expect(malformed.status).toBe(401);
      expect(malformed.body.error.code).toBe("TOKEN_INVALID");
      const extraPart = await request(app)
        .get("/private")
        .set("Authorization", "Bearer token extra");
      expect(extraPart.status).toBe(401);
      const invalid = await request(app)
        .get("/private")
        .set("Authorization", "Bearer forged.token.value");
      expect(invalid.status).toBe(401);
      expect(JSON.stringify(invalid.body)).not.toContain("forged.token.value");

      const expired = await new SignJWT({ token_use: "access" })
        .setProtectedHeader({ alg: "HS256", typ: "JWT" })
        .setSubject("user-1")
        .setIssuer("integration-tests")
        .setAudience("api")
        .setIssuedAt(1)
        .setExpirationTime(2)
        .sign(key);
      const expiredResponse = await request(app)
        .get("/private")
        .set("Authorization", `Bearer ${expired}`);
      expect(expiredResponse.status).toBe(401);
      expect(expiredResponse.body.error.code).toBe("TOKEN_EXPIRED");
    });

    it("authenticates, supports optional auth, and enforces role access", async () => {
      const auth = makeAuth();
      const token = await auth.tokens.generateAccessToken({
        sub: "user-1",
        roles: ["admin"],
      });
      const middleware = createExpressAuth(auth);
      const app = expressImpl();
      app.get(
        "/optional",
        middleware.authenticate({ required: false }),
        (req, res) => res.json({ subject: req.auth?.sub ?? null }),
      );
      app.get(
        "/admin",
        middleware.authenticate(),
        middleware.authorize({ roles: ["admin"] }),
        (_req, res) => res.sendStatus(204),
      );
      app.get(
        "/member",
        middleware.authenticate(),
        middleware.authorize({ roles: ["member"] }),
        (_req, res) => res.sendStatus(204),
      );
      app.get(
        "/role-only",
        middleware.authorize({ roles: ["admin"] }),
        (_req, res) => res.sendStatus(204),
      );
      app.use(middleware.errorHandler());

      expect((await request(app).get("/optional")).body.subject).toBeNull();
      expect(
        (
          await request(app)
            .get("/optional")
            .set("Authorization", "Bearer invalid-token")
        ).status,
      ).toBe(401);
      const success = await request(app)
        .get("/optional")
        .set("Authorization", `Bearer ${token}`);
      expect(success.body.subject).toBe("user-1");
      expect(
        (
          await request(app)
            .get("/admin")
            .set("Authorization", `Bearer ${token}`)
        ).status,
      ).toBe(204);
      const denied = await request(app)
        .get("/member")
        .set("Authorization", `Bearer ${token}`);
      expect(denied.status).toBe(403);
      expect(denied.body.error.code).toBe("FORBIDDEN");
      const unauthenticated = await request(app).get("/role-only");
      expect(unauthenticated.status).toBe(401);
      expect(unauthenticated.body.error.code).toBe("UNAUTHORIZED");

      const noRolesToken = await auth.tokens.generateAccessToken({
        sub: "user-2",
      });
      const noRole = await request(app)
        .get("/member")
        .set("Authorization", `Bearer ${noRolesToken}`);
      expect(noRole.status).toBe(403);
    });

    it("passes the request to isRevoked and allows identity lookup", async () => {
      let hookRequest: unknown;
      const auth = makeAuth((_claims, context) => {
        hookRequest = context;
        return false;
      });
      const token = await auth.tokens.generateAccessToken({ sub: "user-1" });
      const middleware = createExpressAuth(auth, {
        lookupIdentity: async (claims) => ({ ...claims, displayName: "Ada" }),
      });
      const app = expressImpl();
      app.get("/me", middleware.authenticate(), (req, res) =>
        res.json({
          subject: req.auth?.sub,
          displayName: (req.auth as typeof req.auth & { displayName?: string })
            ?.displayName,
        }),
      );
      app.use(middleware.errorHandler());
      const response = await request(app)
        .get("/me")
        .set("Authorization", `Bearer ${token}`);
      expect(response.status).toBe(200);
      expect(response.body.displayName).toBe("Ada");
      expect(hookRequest).toBeDefined();
    });

    it("validates body, params, and query without mutating Express request fields", async () => {
      const auth = makeAuth();
      const token = await auth.tokens.generateAccessToken({
        sub: "user-1",
        roles: ["admin"],
      });
      const middleware = createExpressAuth(auth, { validator: zodAdapter() });
      const schemas = {
        body: z.object({ count: z.coerce.number().int().positive() }),
        params: z.object({ id: z.string().regex(/^item-[0-9]+$/) }),
        query: z.object({ active: z.stringbool() }),
      };
      const app = expressImpl();
      app.use(expressImpl.json());
      app.post(
        "/items/:id",
        middleware.authenticate(),
        middleware.validate(schemas),
        (req, res) =>
          res.json({ validated: req.validated, originalBody: req.body }),
      );
      app.use(middleware.errorHandler());

      const success = await request(app)
        .post("/items/item-7?active=true")
        .set("Authorization", `Bearer ${token}`)
        .send({ count: "3" });
      expect(success.status).toBe(200);
      expect(success.body.validated).toEqual({
        body: { count: 3 },
        params: { id: "item-7" },
        query: { active: true },
      });
      expect(success.body.originalBody).toEqual({ count: "3" });

      for (const [path, body] of [
        ["/items/item-7?active=true", { count: -1 }],
        ["/items/item-7?active=perhaps", { count: 3 }],
        ["/items/not-an-item?active=true", { count: 3 }],
      ] as const) {
        const invalid = await request(app)
          .post(path)
          .set("Authorization", `Bearer ${token}`)
          .send(body);
        expect(invalid.status).toBe(400);
        expect(invalid.body.error.code).toBe("VALIDATION_ERROR");
      }
    });

    it("supports a custom schema formatter and keeps unexpected errors private", async () => {
      const auth = makeAuth();
      const token = await auth.tokens.generateAccessToken({ sub: "user-1" });
      const middleware = createExpressAuth(auth, {
        validator: zodAdapter(),
        errorFormatter: (error) => ({
          status: error.status,
          body: { problem: error.code, detail: error.message },
        }),
      });
      const app = expressImpl();
      app.use(expressImpl.json());
      app.post(
        "/validate",
        middleware.authenticate(),
        middleware.validate({
          body: z.object({ email: z.string().email() }),
          formatError: (_cause, target) =>
            new AuthError("VALIDATION_ERROR", `invalid ${target}`),
        }),
        (_req, res) => res.sendStatus(204),
      );
      app.get("/failure", (_req, _res, next) =>
        next(new Error("private database password")),
      );
      app.use(middleware.errorHandler());

      const invalid = await request(app)
        .post("/validate")
        .set("Authorization", `Bearer ${token}`)
        .send({ email: "bad" });
      expect(invalid.status).toBe(400);
      expect(invalid.body.problem).toBe("VALIDATION_ERROR");
      const failure = await request(app).get("/failure");
      expect(failure.status).toBe(500);
      expect(JSON.stringify(failure.body)).not.toContain(
        "private database password",
      );
      expect(JSON.stringify(failure.body)).not.toContain(
        "integration-test-signing-secret",
      );
    });

    it("supports cookie and composed extractors, and sets secure refresh-cookie defaults", async () => {
      const auth = makeAuth();
      const token = await auth.tokens.generateAccessToken({
        sub: "user-cookie",
      });
      const middleware = createExpressAuth(auth, {
        getToken: fromAny([fromCookie("access"), fromHeader()]),
      });
      const app = expressImpl();
      app.get("/me", middleware.authenticate(), (req, res) =>
        res.json({ subject: req.auth?.sub }),
      );
      app.post("/cookie", (_req, res) => {
        setRefreshTokenCookie(res, "opaque-refresh-token");
        res.sendStatus(204);
      });
      app.use(middleware.errorHandler());
      const response = await request(app)
        .get("/me")
        .set("Cookie", `access=${encodeURIComponent(token)}`);
      expect(response.body.subject).toBe("user-cookie");
      const cookieResponse = await request(app).post("/cookie");
      expect(cookieResponse.headers["set-cookie"]?.[0]).toContain("HttpOnly");
      expect(cookieResponse.headers["set-cookie"]?.[0]).toContain("Secure");
      expect(cookieResponse.headers["set-cookie"]?.[0]).toContain(
        "SameSite=Lax",
      );
    });
  },
);

describe("Express adapter defaults", () => {
  it("allows a custom token extractor while preserving strict header parsing by default", async () => {
    const auth = makeAuth();
    const token = await auth.tokens.generateAccessToken({ sub: "query-user" });
    const middleware = createExpressAuth(auth, {
      getToken: (req) => req.query.access_token as string | undefined,
    });
    const app = express();
    app.get("/me", middleware.authenticate(), (_req, res) =>
      res.sendStatus(204),
    );
    app.use(middleware.errorHandler());
    expect(
      (await request(app).get(`/me?access_token=${encodeURIComponent(token)}`))
        .status,
    ).toBe(204);

    const strict = createExpressAuth(auth);
    const strictApp = express();
    strictApp.get("/me", strict.authenticate(), (_req, res) =>
      res.sendStatus(204),
    );
    strictApp.use(strict.errorHandler());
    expect(
      (
        await request(strictApp).get(
          `/me?access_token=${encodeURIComponent(token)}`,
        )
      ).status,
    ).toBe(401);
    expect(fromHeader()).toBeTypeOf("function");
  });
});
