import { describe, expect, it } from "vitest";
import { AuthError, AUTH_ERROR_CODES, getHttpStatus } from "../src/errors.js";

describe("AuthError", () => {
  it("exposes stable codes, safe public messages and mapped status", () => {
    const error = new AuthError("TOKEN_INVALID", "Signature mismatch");
    expect(error).toBeInstanceOf(Error);
    expect(error.code).toBe("TOKEN_INVALID");
    expect(error.developerMessage).toBe("Signature mismatch");
    expect(error.publicMessage).toBe("Authentication failed");
    expect(error.status).toBe(401);
    expect(getHttpStatus("FORBIDDEN")).toBe(403);
    expect(AUTH_ERROR_CODES).toContain("INVALID_CONFIGURATION");
  });

  it("supports custom safe messages and causes", () => {
    const cause = new Error("internal detail");
    const error = new AuthError("INVALID_CONFIGURATION", "bad key", {
      publicMessage: "Unavailable",
      cause,
    });
    expect(error.publicMessage).toBe("Unavailable");
    expect(error.cause).toBe(cause);
  });
});
