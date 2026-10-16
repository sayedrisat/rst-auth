/** A framework-independent schema validator used by optional adapters. */
export interface ValidatorAdapter {
  parse<TSchema>(schema: TSchema, value: unknown): unknown | Promise<unknown>;
}

export type ValidationTarget = "body" | "params" | "query";

export type ValidationSchemaMap<TSchema = unknown> = Partial<
  Record<ValidationTarget, TSchema>
>;
