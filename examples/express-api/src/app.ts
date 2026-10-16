import express, {
  type Express,
  type NextFunction,
  type Request,
  type RequestHandler,
  type Response,
} from "express";
import { createAuth, MemoryRefreshTokenStore, AuthError } from "rst-auth";
import {
  expressAuth,
  fromCookie,
  setRefreshTokenCookie,
  clearRefreshTokenCookie,
} from "rst-auth/express";
import { zodAdapter } from "rst-auth/zod";
import { z } from "zod";
import { InMemoryUserRepository, type User } from "./user-repository.js";

const signupSchema = z
  .object({ email: z.string().email(), password: z.string().min(1) })
  .strict();
const loginSchema = z
  .object({ email: z.string().email(), password: z.string().min(1) })
  .strict();
const refreshSchema = z
  .object({ refreshToken: z.string().min(1).optional() })
  .strict()
  .optional();

export interface ExampleAppOptions {
  accessTokenSecret: string;
  repository?: InMemoryUserRepository;
}

export interface ExampleApp {
  app: Express;
  auth: ReturnType<typeof createAuth>;
  repository: InMemoryUserRepository;
}

type SessionBody = { email: string; password: string };
type RefreshBody = { refreshToken?: string } | undefined;

function asyncRoute(
  handler: (request: Request, response: Response) => Promise<void>,
): RequestHandler {
  return (request, response, next: NextFunction) => {
    void handler(request, response).catch(next);
  };
}

function validatedBody<T>(request: Request): T {
  return request.validated?.body as T;
}

export function createExampleApp({
  accessTokenSecret,
  repository = new InMemoryUserRepository(),
}: ExampleAppOptions): ExampleApp {
  if (Buffer.byteLength(accessTokenSecret, "utf8") < 32) {
    throw new Error("ACCESS_TOKEN_SECRET must contain at least 32 UTF-8 bytes");
  }

  const auth = createAuth({
    password: { workFactor: 4 },
    accessToken: {
      key: new TextEncoder().encode(accessTokenSecret),
      issuer: "rst-auth-example",
      audience: "example-api",
    },
    refreshToken: {
      store: new MemoryRefreshTokenStore(), // Local demonstration only.
      refreshTokenTtl: 60 * 60 * 24 * 7,
      absoluteLifetime: 60 * 60 * 24 * 30,
    },
  });
  const middleware = expressAuth(auth, {
    validator: zodAdapter(),
    errorFormatter: (error) => ({
      status: error.status,
      body: { error: { code: error.code, message: error.message } },
    }),
  });
  const app = express();
  app.use(express.json());

  async function sendSession(
    user: User,
    response: Response,
    useCookie: boolean,
  ) {
    const accessToken = await auth.tokens.generateAccessToken({
      sub: user.id,
      role: user.role,
    });
    const refresh = await auth.refresh!.issue({ subject: user.id });
    if (useCookie) {
      setRefreshTokenCookie(response, refresh.refreshToken, {
        maxAge: 7 * 24 * 60 * 60 * 1000,
      });
      response.status(200).json({
        user: { id: user.id, email: user.email, role: user.role },
        accessToken,
      });
      return;
    }
    response.status(200).json({
      user: { id: user.id, email: user.email, role: user.role },
      accessToken,
      refreshToken: refresh.refreshToken,
    });
  }

  async function signup(request: Request, response: Response) {
    const { email, password } = validatedBody<SessionBody>(request);
    const existing = await repository.findByEmail(email);
    if (existing) {
      throw new AuthError(
        "VALIDATION_ERROR",
        "An account already exists for this email",
      );
    }
    const passwordHash = await auth.password.hash(password);
    const user = await repository.create(email, passwordHash);
    if (!user) {
      throw new AuthError(
        "VALIDATION_ERROR",
        "An account already exists for this email",
      );
    }
    await sendSession(user, response, request.path.endsWith("/cookie"));
  }

  async function login(request: Request, response: Response) {
    const { email, password } = validatedBody<SessionBody>(request);
    const user = await repository.findByEmail(email);
    if (!user) {
      await auth.password.verifyDummy(password);
      throw new AuthError("UNAUTHORIZED", "Invalid email or password");
    }
    if (!(await auth.password.verify(password, user.passwordHash))) {
      throw new AuthError("UNAUTHORIZED", "Invalid email or password");
    }
    await sendSession(user, response, request.path.endsWith("/cookie"));
  }

  app.post(
    "/auth/signup",
    middleware.validate({ body: signupSchema }),
    asyncRoute(signup),
  );
  app.post(
    "/auth/login",
    middleware.validate({ body: loginSchema }),
    asyncRoute(login),
  );
  app.post(
    "/auth/login/cookie",
    middleware.validate({ body: loginSchema }),
    asyncRoute(login),
  );

  app.post(
    "/auth/refresh",
    middleware.validate({ body: refreshSchema }),
    asyncRoute(async (request, response) => {
      const body = validatedBody<RefreshBody>(request);
      const cookieToken = await fromCookie("refreshToken")(request);
      const refreshToken = body?.refreshToken ?? cookieToken;
      if (!refreshToken) {
        throw new AuthError("TOKEN_MISSING", "Refresh token is required");
      }
      const rotated = await auth.refresh!.rotate(refreshToken);
      const user = await repository.findById(rotated.subject);
      if (!user) {
        await auth.refresh!.revoke(rotated.refreshToken);
        throw new AuthError("UNAUTHORIZED", "The account is unavailable");
      }
      const accessToken = await auth.tokens.generateAccessToken({
        sub: user.id,
        role: user.role,
      });
      if (body?.refreshToken === undefined && cookieToken !== undefined) {
        setRefreshTokenCookie(response, rotated.refreshToken, {
          maxAge: Math.max(0, rotated.expiresAt.getTime() - Date.now()),
        });
        response.json({ accessToken });
        return;
      }
      response.json({ accessToken, refreshToken: rotated.refreshToken });
    }),
  );

  app.post(
    "/auth/logout",
    middleware.validate({ body: refreshSchema }),
    asyncRoute(async (request, response) => {
      const body = validatedBody<RefreshBody>(request);
      const cookieToken = await fromCookie("refreshToken")(request);
      const refreshToken = body?.refreshToken ?? cookieToken;
      if (refreshToken) await auth.refresh!.revoke(refreshToken);
      clearRefreshTokenCookie(response);
      response.sendStatus(204);
    }),
  );

  app.get("/me", middleware.authenticate(), (request, response) => {
    response.json({ subject: request.auth?.sub, role: request.auth?.role });
  });
  app.get(
    "/admin",
    middleware.authenticate(),
    middleware.authorize({ roles: ["admin"] }),
    (_request, response) => response.json({ message: "Admin access granted" }),
  );

  app.use(middleware.errorHandler());
  return { app, auth, repository };
}
