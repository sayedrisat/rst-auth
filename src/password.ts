import bcrypt from "bcryptjs";
import { AuthError } from "./errors.js";

const MAX_PASSWORD_BYTES = 72;

function validatePassword(password: unknown): asserts password is string {
  if (typeof password !== "string" || password.length === 0) {
    throw new AuthError(
      "VALIDATION_ERROR",
      "Password must be a non-empty string",
    );
  }
  if (Buffer.byteLength(password, "utf8") > MAX_PASSWORD_BYTES) {
    throw new AuthError(
      "VALIDATION_ERROR",
      "Password must not exceed 72 UTF-8 bytes because bcrypt truncates longer values",
    );
  }
}

export interface PasswordService {
  hash(password: string): Promise<string>;
  verify(password: string, hash: string): Promise<boolean>;
  verifyDummy(password: string): Promise<void>;
}

export function createPasswordService(workFactor: number): PasswordService {
  const dummyHash = bcrypt.hashSync(
    "rst-auth-dummy-password-value",
    workFactor,
  );

  return {
    async hash(password: string): Promise<string> {
      validatePassword(password);
      return bcrypt.hash(password, workFactor);
    },

    async verify(password: string, hash: string): Promise<boolean> {
      validatePassword(password);
      if (typeof hash !== "string" || hash.length === 0) return false;
      try {
        return await bcrypt.compare(password, hash);
      } catch {
        return false;
      }
    },

    async verifyDummy(password: string): Promise<void> {
      validatePassword(password);
      await bcrypt.compare(password, dummyHash);
    },
  };
}
