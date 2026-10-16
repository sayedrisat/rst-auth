# Request validation

The Express adapter accepts a framework-independent `ValidatorAdapter`. `rst-auth/zod` provides `zodAdapter()` and supports async Zod parsing. Apps can implement the same small interface for another validator.

```ts
const middleware = expressAuth(auth, { validator: zodAdapter() });
app.post(
  "/users/:id",
  middleware.validate({
    body: bodySchema,
    params: paramsSchema,
    query: querySchema,
  }),
  (req, res) => {
    const body = req.validated?.body;
    const params = req.validated?.params;
    res.json({ body, params });
  },
);
```

Only configured targets are parsed. Parsed data is assigned to `req.validated.body`, `.params`, and `.query`; source request properties are not replaced. This is important for Express 5, whose `req.query` is a getter. A validation failure becomes `VALIDATION_ERROR` (HTTP 400) by default. Provide `formatError` on the validation schema options for target-specific mapping, or configure the Express `errorFormatter` for the public response shape. Formatters should emit only information safe for clients.

Zod output types are inferred by Zod itself. For a schema-specific request view, the Express subpath exports `ValidatedRequest<TSchemas>`; global request augmentation stays broad so different routes can use different schemas.
