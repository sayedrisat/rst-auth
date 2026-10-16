import type { AuthConfig } from "./config.js";
import { validateAuthConfig } from "./config.js";
import { AuthError, AUTH_ERROR_CODES, getHttpStatus } from "./errors.js";
import { createPasswordService } from "./password.js";
import { createAccessTokenService } from "./tokens.js";
import {
  createRefreshTokenService,
  type RefreshTokenService,
} from "./refresh.js";
import { MemoryRefreshTokenStore } from "./memory-refresh-token-store.js";

export interface Auth {
  password: ReturnType<typeof createPasswordService>;
  tokens: ReturnType<typeof createAccessTokenService>;
  refresh?: RefreshTokenService;
}

export function createAuth(config: AuthConfig): Auth {
  const validatedConfig = validateAuthConfig(config);
  const refresh = validatedConfig.refreshToken
    ? createRefreshTokenService(validatedConfig.refreshToken)
    : undefined;
  return {
    password: createPasswordService(validatedConfig.password.workFactor),
    tokens: createAccessTokenService(validatedConfig.accessToken),
    ...(refresh === undefined ? {} : { refresh }),
  };
}

export { MemoryRefreshTokenStore };
export { AuthError, AUTH_ERROR_CODES, getHttpStatus };
export type {
  ConsumeResult,
  RefreshTokenRecord,
  RefreshTokenStatus,
  RefreshTokenStore,
  RevokeTokenResult,
} from "./refresh-store.js";
export type {
  IssuedRefreshToken,
  IssueRefreshTokenInput,
  RefreshTokenService,
} from "./refresh.js";
export type { AuthErrorCode, AuthErrorOptions } from "./errors.js";
export type {
  AuthConfig,
  KeyResolver,
  RuntimeMode,
  SupportedAlgorithm,
  TokenKey,
} from "./config.js";
export type {
  AccessTokenClaims,
  AccessTokenService,
  VerifiedAccessClaims,
} from "./tokens.js";
export type {
  ValidationSchemaMap,
  ValidationTarget,
  ValidatorAdapter,
} from "./validation.js";
