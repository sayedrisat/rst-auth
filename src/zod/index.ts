import type { ZodType } from "zod";
import { AuthError } from "../errors.js";
import type { ValidatorAdapter } from "../validation.js";

export type ZodAdapter = ValidatorAdapter;

/** Adapts Zod 3 or 4 schemas to the framework-independent validator interface. */
export function zodAdapter(): ZodAdapter {
  return {
    async parse(schema: unknown, value: unknown): Promise<unknown> {
      if (
        !schema ||
        typeof schema !== "object" ||
        !("safeParseAsync" in schema)
      ) {
        throw new TypeError("The Zod adapter requires a Zod schema");
      }
      const zodSchema = schema as ZodType;
      const result = await zodSchema.safeParseAsync(value);
      if (!result.success) {
        throw new AuthError("VALIDATION_ERROR", "Request validation failed", {
          cause: result.error,
        });
      }
      return result.data;
    },
  };
}
