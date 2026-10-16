import type { CompactJWSHeaderParameters, KeyInput } from "jose";
import { AuthError } from "./errors.js";
import type { RefreshTokenStore } from "./refresh-store.js";

export const DEFAULT_BCRYPT_ROUNDS = 12;
export const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 900;
const MAX_REFRESH_LIFETIME_SECONDS = 8_000_000_000_000;
export const SUPPORTED_ALGORITHMS = [
  "HS256",
  "HS384",
  "HS512",
  "RS256",
  "RS384",
  "RS512",
  "PS256",
  "PS384",
  "PS512",
  "ES256",
  "ES384",
  "ES512",
  "EdDSA",
] as const;

export type SupportedAlgorithm = (typeof SUPPORTED_ALGORITHMS)[number];
export type RuntimeMode = "development" | "production";
export type TokenKey = KeyInput;
export type KeyResolver = (
  header: CompactJWSHeaderParameters,
) => TokenKey | Promise<TokenKey>;

export interface AuthConfig {
  mode?: RuntimeMode;
  password?: {
    workFactor?: number;
  };
  accessToken: {
    algorithm?: SupportedAlgorithm;
    algorithms?: readonly SupportedAlgorithm[];
    key: TokenKey;
    keyId?: string;
    keyResolver?: KeyResolver;
    issuer?: string;
    audience?: string | readonly string[];
    expiresInSeconds?: number;
    requiredClaims?: readonly string[];
    isRevoked?: (
      claims: Readonly<Record<string, unknown>>,
      context?: unknown,
    ) => boolean | Promise<boolean>;
  };
  /** Omit to disable refresh-token support. A configured refresh store is mandatory. */
  refreshToken?: {
    store: RefreshTokenStore;
    refreshTokenTtl: number;
    absoluteLifetime: number;
  };
}

export interface ValidatedAuthConfig {
  mode: RuntimeMode;
  password: { workFactor: number };
  accessToken: {
    algorithm: SupportedAlgorithm;
    algorithms: readonly SupportedAlgorithm[];
    key: TokenKey;
    keyId?: string;
    keyResolver?: KeyResolver;
    issuer?: string;
    audience?: string | readonly string[];
    expiresInSeconds: number;
    requiredClaims: readonly string[];
    isRevoked?: AuthConfig["accessToken"]["isRevoked"];
  };
  refreshToken?: {
    store: RefreshTokenStore;
    refreshTokenTtl: number;
    absoluteLifetime: number;
  };
}

const RESERVED_CLAIMS = new Set([
  "iss",
  "aud",
  "exp",
  "iat",
  "nbf",
  "jti",
  "token_use",
]);

export function isReservedClaim(name: string): boolean {
  return RESERVED_CLAIMS.has(name);
}

function invalid(message: string): never {
  throw new AuthError("INVALID_CONFIGURATION", message);
}

function validateKey(key: TokenKey, algorithm: SupportedAlgorithm): void {
  if (algorithm.startsWith("HS")) {
    if (!(key instanceof Uint8Array) || key.byteLength < 32) {
      invalid(
        "HMAC access-token keys must be Uint8Array values of at least 32 bytes",
      );
    }
    return;
  }

  if (key instanceof Uint8Array) {
    invalid(`${algorithm} requires a CryptoKey or KeyObject, not a byte array`);
  }
}

export function validateAuthConfig(config: AuthConfig): ValidatedAuthConfig {
  if (!config || typeof config !== "object") {
    invalid("Configuration must be an object");
  }

  const mode = config.mode ?? "development";
  if (mode !== "development" && mode !== "production") {
    invalid('mode must be "development" or "production"');
  }

  if (
    config.password !== undefined &&
    (typeof config.password !== "object" || config.password === null)
  ) {
    invalid("password must be an object when provided");
  }
  const workFactor = config.password?.workFactor ?? DEFAULT_BCRYPT_ROUNDS;
  if (!Number.isInteger(workFactor) || workFactor < 4 || workFactor > 31) {
    invalid("password.workFactor must be an integer between 4 and 31");
  }

  const tokenConfig = config.accessToken;
  if (!tokenConfig || typeof tokenConfig !== "object" || !tokenConfig.key) {
    invalid("accessToken.key is required");
  }

  const algorithm = tokenConfig.algorithm ?? "HS256";
  if (!(SUPPORTED_ALGORITHMS as readonly string[]).includes(algorithm)) {
    invalid("accessToken.algorithm is not supported");
  }
  const algorithms = [...new Set(tokenConfig.algorithms ?? [algorithm])];
  if (
    algorithms.length === 0 ||
    !algorithms.includes(algorithm) ||
    algorithms.some(
      (entry) => !(SUPPORTED_ALGORITHMS as readonly string[]).includes(entry),
    )
  ) {
    invalid(
      "accessToken.algorithms must be a non-empty allowlist containing the signing algorithm",
    );
  }
  validateKey(tokenConfig.key, algorithm);

  const expiresInSeconds =
    tokenConfig.expiresInSeconds ?? DEFAULT_ACCESS_TOKEN_TTL_SECONDS;
  if (!Number.isSafeInteger(expiresInSeconds) || expiresInSeconds <= 0) {
    invalid("accessToken.expiresInSeconds must be a positive safe integer");
  }
  if (
    tokenConfig.issuer !== undefined &&
    (typeof tokenConfig.issuer !== "string" || tokenConfig.issuer.length === 0)
  ) {
    invalid("accessToken.issuer must be a non-empty string when provided");
  }
  if (tokenConfig.audience !== undefined) {
    const audience = tokenConfig.audience;
    if (!(
      (typeof audience === "string" && audience.length > 0) ||
      (Array.isArray(audience) &&
        audience.length > 0 &&
        audience.every((item) => typeof item === "string" && item.length > 0))
    )) {
      invalid("accessToken.audience must contain non-empty string values");
    }
  }
  if (mode === "production") {
    if (!tokenConfig.issuer || !tokenConfig.audience) {
      invalid(
        "Production mode requires accessToken.issuer and accessToken.audience",
      );
    }
    if (expiresInSeconds > 3600) {
      invalid("Production access tokens must expire within one hour");
    }
  }
  if (tokenConfig.keyId !== undefined && tokenConfig.keyId.length === 0) {
    invalid("accessToken.keyId must be non-empty when provided");
  }
  if (
    tokenConfig.keyResolver !== undefined &&
    typeof tokenConfig.keyResolver !== "function"
  ) {
    invalid("accessToken.keyResolver must be a function");
  }
  if (
    tokenConfig.requiredClaims !== undefined &&
    !Array.isArray(tokenConfig.requiredClaims)
  ) {
    invalid("accessToken.requiredClaims must be an array");
  }
  if (
    tokenConfig.isRevoked !== undefined &&
    typeof tokenConfig.isRevoked !== "function"
  ) {
    invalid("accessToken.isRevoked must be a function");
  }

  let refreshToken: ValidatedAuthConfig["refreshToken"];
  if (config.refreshToken !== undefined) {
    const refreshConfig = config.refreshToken;
    if (!refreshConfig || typeof refreshConfig !== "object") {
      invalid("refreshToken must be an object when provided");
    }
    const store = refreshConfig.store as
      (RefreshTokenStore & Record<string, unknown>) | undefined;
    if (
      !store ||
      typeof store.create !== "function" ||
      typeof store.consume !== "function" ||
      typeof store.revokeToken !== "function" ||
      typeof store.revokeFamily !== "function" ||
      typeof store.revokeAllForSubject !== "function"
    ) {
      invalid(
        "refreshToken.store must implement the complete RefreshTokenStore interface",
      );
    }
    if (
      !Number.isSafeInteger(refreshConfig.refreshTokenTtl) ||
      refreshConfig.refreshTokenTtl <= 0 ||
      refreshConfig.refreshTokenTtl > MAX_REFRESH_LIFETIME_SECONDS
    ) {
      invalid(
        "refreshToken.refreshTokenTtl must be a positive safe integer in seconds",
      );
    }
    if (
      !Number.isSafeInteger(refreshConfig.absoluteLifetime) ||
      refreshConfig.absoluteLifetime <= 0 ||
      refreshConfig.absoluteLifetime > MAX_REFRESH_LIFETIME_SECONDS
    ) {
      invalid(
        "refreshToken.absoluteLifetime must be a positive safe integer in seconds",
      );
    }
    refreshToken = {
      store,
      refreshTokenTtl: refreshConfig.refreshTokenTtl,
      absoluteLifetime: refreshConfig.absoluteLifetime,
    };
  }
  const requiredClaims = [
    ...new Set([
      "sub",
      "iat",
      "exp",
      ...(tokenConfig.issuer ? ["iss"] : []),
      ...(tokenConfig.audience ? ["aud"] : []),
      ...(tokenConfig.requiredClaims ?? []),
    ]),
  ];
  if (requiredClaims.some((claim) => typeof claim !== "string" || !claim)) {
    invalid("accessToken.requiredClaims must contain non-empty claim names");
  }

  return {
    mode,
    password: { workFactor },
    accessToken: {
      algorithm,
      algorithms,
      key: tokenConfig.key,
      ...(tokenConfig.keyId === undefined ? {} : { keyId: tokenConfig.keyId }),
      ...(tokenConfig.keyResolver === undefined
        ? {}
        : { keyResolver: tokenConfig.keyResolver }),
      ...(tokenConfig.issuer === undefined
        ? {}
        : { issuer: tokenConfig.issuer }),
      ...(tokenConfig.audience === undefined
        ? {}
        : { audience: tokenConfig.audience }),
      expiresInSeconds,
      requiredClaims,
      ...(tokenConfig.isRevoked === undefined
        ? {}
        : { isRevoked: tokenConfig.isRevoked }),
    },
    ...(refreshToken === undefined ? {} : { refreshToken }),
  };
}
