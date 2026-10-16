export const AUTH_ERROR_CODES = [
  "TOKEN_MISSING",
  "TOKEN_INVALID",
  "TOKEN_EXPIRED",
  "REFRESH_TOKEN_INVALID",
  "REFRESH_TOKEN_REUSED",
  "SESSION_REVOKED",
  "UNAUTHORIZED",
  "FORBIDDEN",
  "VALIDATION_ERROR",
  "INVALID_CONFIGURATION",
] as const;

export type AuthErrorCode = (typeof AUTH_ERROR_CODES)[number];

const HTTP_STATUS: Record<AuthErrorCode, number> = {
  TOKEN_MISSING: 401,
  TOKEN_INVALID: 401,
  TOKEN_EXPIRED: 401,
  REFRESH_TOKEN_INVALID: 401,
  REFRESH_TOKEN_REUSED: 401,
  SESSION_REVOKED: 401,
  UNAUTHORIZED: 401,
  FORBIDDEN: 403,
  VALIDATION_ERROR: 400,
  INVALID_CONFIGURATION: 500,
};

const PUBLIC_MESSAGES: Record<AuthErrorCode, string> = {
  TOKEN_MISSING: "Authentication is required",
  TOKEN_INVALID: "Authentication failed",
  TOKEN_EXPIRED: "Authentication has expired",
  REFRESH_TOKEN_INVALID: "Refresh token is invalid",
  REFRESH_TOKEN_REUSED: "Refresh token is invalid",
  SESSION_REVOKED: "Authentication has been revoked",
  UNAUTHORIZED: "Authentication is required",
  FORBIDDEN: "You are not allowed to perform this action",
  VALIDATION_ERROR: "The request is invalid",
  INVALID_CONFIGURATION: "Authentication is unavailable",
};

export interface AuthErrorOptions {
  publicMessage?: string;
  status?: number;
  cause?: unknown;
}

export class AuthError extends Error {
  readonly code: AuthErrorCode;
  readonly developerMessage: string;
  readonly publicMessage: string;
  readonly status: number;

  constructor(
    code: AuthErrorCode,
    developerMessage: string,
    options: AuthErrorOptions = {},
  ) {
    super(developerMessage, { cause: options.cause });
    this.name = "AuthError";
    this.code = code;
    this.developerMessage = developerMessage;
    this.publicMessage = options.publicMessage ?? PUBLIC_MESSAGES[code];
    this.status = options.status ?? HTTP_STATUS[code];
  }
}

export function getHttpStatus(code: AuthErrorCode): number {
  return HTTP_STATUS[code];
}
