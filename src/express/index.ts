import type {
  ErrorRequestHandler,
  NextFunction,
  Request,
  RequestHandler,
  Response,
} from "express";
import { AuthError } from "../errors.js";
import type { Auth } from "../index.js";
import type {
  ValidationSchemaMap,
  ValidationTarget,
  ValidatorAdapter,
} from "../validation.js";
import type { VerifiedAccessClaims } from "../tokens.js";

export interface AuthenticatedRequest<
  Identity extends VerifiedAccessClaims = VerifiedAccessClaims,
> extends Request {
  auth?: Identity;
  validated?: Partial<Record<ValidationTarget, unknown>>;
}

type SchemaOutput<TSchema> = TSchema extends { _output: infer TOutput }
  ? TOutput
  : unknown;

export type ValidatedRequest<TSchemas extends ValidationSchemaMap> = Request & {
  validated?: {
    [Target in keyof TSchemas]?: SchemaOutput<TSchemas[Target]>;
  };
};

declare module "express-serve-static-core" {
  interface Request {
    auth?: VerifiedAccessClaims;
    validated?: Partial<Record<ValidationTarget, unknown>>;
  }
}

export type TokenExtractor = (
  request: Request,
) => string | undefined | Promise<string | undefined>;

export interface PublicHttpError {
  status: number;
  code: string;
  message: string;
}

export interface FormattedHttpError {
  status: number;
  body: unknown;
}

export type ErrorFormatter = (
  error: PublicHttpError,
  request: Request,
) => FormattedHttpError;

export type IdentityLookup<Identity extends VerifiedAccessClaims> = (
  claims: VerifiedAccessClaims,
  request: Request,
) => Identity | null | Promise<Identity | null>;

export interface ExpressAuthOptions<Identity extends VerifiedAccessClaims> {
  getToken?: TokenExtractor;
  lookupIdentity?: IdentityLookup<Identity>;
  validator?: ValidatorAdapter;
  errorFormatter?: ErrorFormatter;
}

export interface AuthenticateOptions {
  required?: boolean;
}

export interface AuthorizeOptions {
  roles: readonly string[];
}

const defaultErrorFormatter: ErrorFormatter = (error) => ({
  status: error.status,
  body: { error: { code: error.code, message: error.message } },
});

function publicError(error: unknown): PublicHttpError {
  if (error instanceof AuthError) {
    return {
      status: error.status,
      code: error.code,
      message: error.publicMessage,
    };
  }
  return {
    status: 500,
    code: "INTERNAL_ERROR",
    message: "Internal server error",
  };
}

function asyncHandler(
  handler: (
    request: Request,
    response: Response,
    next: NextFunction,
  ) => void | Promise<void>,
): RequestHandler {
  return (request, response, next) => {
    void Promise.resolve()
      .then(() => handler(request, response, next))
      .catch(next);
  };
}

export function fromHeader(): TokenExtractor {
  return (request) => {
    const value = request.get("authorization");
    if (value === undefined) return undefined;
    const match = /^Bearer[ \t]+([^\s,]+)$/i.exec(value);
    if (!match?.[1]) {
      throw new AuthError("TOKEN_INVALID", "Malformed Authorization header");
    }
    return match[1];
  };
}

export function fromCookie(name: string): TokenExtractor {
  if (!name || /[=;\s]/.test(name)) {
    throw new TypeError("Cookie name must be a non-empty token");
  }
  return (request) => {
    const header = request.get("cookie");
    if (!header) return undefined;
    for (const entry of header.split(";")) {
      const separator = entry.indexOf("=");
      if (separator < 0 || entry.slice(0, separator).trim() !== name) continue;
      const value = entry.slice(separator + 1).trim();
      try {
        return decodeURIComponent(value);
      } catch {
        throw new AuthError("TOKEN_INVALID", "Malformed authentication cookie");
      }
    }
    return undefined;
  };
}

export function fromAny(extractors: readonly TokenExtractor[]): TokenExtractor {
  if (!extractors.length)
    throw new TypeError("At least one extractor is required");
  return async (request) => {
    for (const extract of extractors) {
      const token = await extract(request);
      if (token !== undefined) return token;
    }
    return undefined;
  };
}

export type ValidateOptions<
  TSchemas extends ValidationSchemaMap = ValidationSchemaMap,
> = {
  [Target in keyof TSchemas]?: TSchemas[Target];
} & {
  formatError?: (cause: unknown, target: ValidationTarget) => AuthError;
};

export function expressAuth<
  Identity extends VerifiedAccessClaims = VerifiedAccessClaims,
>(auth: Auth, options: ExpressAuthOptions<Identity> = {}) {
  const extractToken = options.getToken ?? fromHeader();

  function authenticate(
    authenticateOptions: AuthenticateOptions = {},
  ): RequestHandler {
    const required = authenticateOptions.required ?? true;
    return asyncHandler(async (request, _response, next) => {
      const token = await extractToken(request);
      if (token === undefined) {
        if (required) {
          throw new AuthError("TOKEN_MISSING", "Access token is required");
        }
        delete request.auth;
        next();
        return;
      }
      const claims = await auth.tokens.verifyAccessToken(token, request);
      const identity = options.lookupIdentity
        ? await options.lookupIdentity(claims, request)
        : (claims as Identity);
      if (identity === null) {
        throw new AuthError(
          "UNAUTHORIZED",
          "Identity lookup did not find a user",
        );
      }
      request.auth = identity;
      next();
    });
  }

  function authorize(authorizeOptions: AuthorizeOptions): RequestHandler {
    const requiredRoles = new Set(authorizeOptions.roles);
    return (request, _response, next) => {
      if (!request.auth) {
        next(new AuthError("UNAUTHORIZED", "Authentication is required"));
        return;
      }
      const roleData = request.auth as VerifiedAccessClaims & {
        role?: unknown;
        roles?: unknown;
      };
      const userRoles = [
        ...(typeof roleData.role === "string" ? [roleData.role] : []),
        ...(Array.isArray(roleData.roles)
          ? roleData.roles.filter(
              (role): role is string => typeof role === "string",
            )
          : []),
      ];
      if (!userRoles.some((role) => requiredRoles.has(role))) {
        next(new AuthError("FORBIDDEN", "User does not have a required role"));
        return;
      }
      next();
    };
  }

  function validate<TSchemas extends ValidationSchemaMap>(
    schemas: ValidateOptions<TSchemas>,
  ): RequestHandler {
    if (!options.validator) {
      throw new AuthError(
        "INVALID_CONFIGURATION",
        "A validator adapter must be configured before using validate()",
      );
    }
    const targets: ValidationTarget[] = ["body", "params", "query"];
    return asyncHandler(async (request, _response, next) => {
      const parsed: Partial<Record<ValidationTarget, unknown>> = {};
      for (const target of targets) {
        const schema = schemas[target];
        if (schema === undefined) continue;
        try {
          parsed[target] = await options.validator!.parse(
            schema,
            request[target],
          );
        } catch (cause) {
          throw (
            schemas.formatError?.(cause, target) ??
            new AuthError("VALIDATION_ERROR", `Invalid request ${target}`, {
              cause,
            })
          );
        }
      }
      request.validated = parsed;
      next();
    });
  }

  function errorHandler(
    formatter: ErrorFormatter = options.errorFormatter ?? defaultErrorFormatter,
  ): ErrorRequestHandler {
    return (error: unknown, request, response, next) => {
      if (response.headersSent) {
        next(error);
        return;
      }
      const formatted = formatter(publicError(error), request);
      response.status(formatted.status).json(formatted.body);
    };
  }

  return { authenticate, authorize, validate, errorHandler };
}

/** Alias retained for callers who prefer the create* naming convention. */
export const createExpressAuth = expressAuth;

export interface RefreshCookieOptions {
  name?: string;
  path?: string;
  maxAge?: number;
  secure?: boolean;
  sameSite?: "lax" | "strict" | "none";
}

function cookieSettings(options: RefreshCookieOptions = {}) {
  const secure = options.secure ?? true;
  const sameSite = options.sameSite ?? "lax";
  if (sameSite === "none" && !secure) {
    throw new TypeError("SameSite=None cookies require Secure");
  }
  return {
    httpOnly: true,
    secure,
    sameSite,
    path: options.path ?? "/auth/refresh",
    ...(options.maxAge === undefined ? {} : { maxAge: options.maxAge }),
  };
}

export function setRefreshTokenCookie(
  response: Response,
  token: string,
  options: RefreshCookieOptions = {},
): void {
  response.cookie(
    options.name ?? "refreshToken",
    token,
    cookieSettings(options),
  );
}

export function clearRefreshTokenCookie(
  response: Response,
  options: RefreshCookieOptions = {},
): void {
  const settings = cookieSettings(options);
  response.clearCookie(options.name ?? "refreshToken", {
    httpOnly: settings.httpOnly,
    secure: settings.secure,
    sameSite: settings.sameSite,
    path: settings.path,
  });
}

export type {
  ValidatorAdapter,
  ValidationSchemaMap,
  ValidationTarget,
} from "../validation.js";
