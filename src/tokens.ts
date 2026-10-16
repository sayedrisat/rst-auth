import { SignJWT, jwtVerify, type JWTPayload } from "jose";
import type { ValidatedAuthConfig } from "./config.js";
import { isReservedClaim } from "./config.js";
import { AuthError } from "./errors.js";

export type AccessTokenClaims = JWTPayload & { sub: string };
export type VerifiedAccessClaims = JWTPayload & {
  sub: string;
  token_use: "access";
};

export interface AccessTokenService {
  generateAccessToken(claims: AccessTokenClaims): Promise<string>;
  verifyAccessToken(
    token: string,
    context?: unknown,
  ): Promise<VerifiedAccessClaims>;
}

export function createAccessTokenService(
  config: ValidatedAuthConfig["accessToken"],
): AccessTokenService {
  return {
    async generateAccessToken(claims): Promise<string> {
      if (
        !claims ||
        typeof claims !== "object" ||
        typeof claims.sub !== "string" ||
        !claims.sub
      ) {
        throw new AuthError(
          "VALIDATION_ERROR",
          "Access-token claims require a non-empty sub",
        );
      }
      for (const claim of Object.keys(claims)) {
        if (isReservedClaim(claim)) {
          throw new AuthError(
            "VALIDATION_ERROR",
            `Caller-supplied claim ${claim} is reserved by the access-token implementation`,
          );
        }
      }

      let jwt = new SignJWT({ ...claims, token_use: "access" })
        .setProtectedHeader({
          alg: config.algorithm,
          typ: "JWT",
          ...(config.keyId === undefined ? {} : { kid: config.keyId }),
        })
        .setIssuedAt()
        .setExpirationTime(`${config.expiresInSeconds}s`);
      if (config.issuer) jwt = jwt.setIssuer(config.issuer);
      if (config.audience) {
        jwt = jwt.setAudience(
          typeof config.audience === "string"
            ? config.audience
            : [...config.audience],
        );
      }
      return jwt.sign(config.key);
    },

    async verifyAccessToken(token, context): Promise<VerifiedAccessClaims> {
      if (typeof token !== "string" || token.length === 0) {
        throw new AuthError("TOKEN_MISSING", "Access token is required");
      }

      try {
        const verified = await jwtVerify(
          token,
          async (header) => {
            if (config.keyResolver) {
              if (typeof header.kid !== "string" || header.kid.length === 0) {
                throw new AuthError(
                  "TOKEN_INVALID",
                  "Access token key identifier is missing",
                );
              }
              return config.keyResolver(header);
            }
            return config.key;
          },
          {
            algorithms: [...config.algorithms],
            ...(config.issuer ? { issuer: config.issuer } : {}),
            ...(config.audience
              ? {
                  audience:
                    typeof config.audience === "string"
                      ? config.audience
                      : [...config.audience],
                }
              : {}),
            requiredClaims: [...config.requiredClaims],
          },
        );
        const claims = verified.payload;
        if (claims.token_use !== "access") {
          throw new AuthError("TOKEN_INVALID", "Token is not an access token");
        }
        if (config.isRevoked && (await config.isRevoked(claims, context))) {
          throw new AuthError(
            "SESSION_REVOKED",
            "Access token has been revoked",
          );
        }
        if (typeof claims.sub !== "string") {
          throw new AuthError(
            "TOKEN_INVALID",
            "Access token has no valid subject",
          );
        }
        return claims as VerifiedAccessClaims;
      } catch (error) {
        if (error instanceof AuthError) throw error;
        if (
          typeof error === "object" &&
          error !== null &&
          "code" in error &&
          error.code === "ERR_JWT_EXPIRED"
        ) {
          throw new AuthError("TOKEN_EXPIRED", "Access token has expired", {
            cause: error,
          });
        }
        throw new AuthError("TOKEN_INVALID", "Access token is invalid", {
          cause: error,
        });
      }
    },
  };
}
