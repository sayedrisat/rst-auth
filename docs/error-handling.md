# Error handling

`AuthError` contains a stable code, developer message, safe `publicMessage`, HTTP status, and optional cause. Common status mapping is 401 for missing/invalid/expired/revoked authentication, 403 for forbidden access, and 400 for validation. Configuration errors are server errors and should be caught during startup.

```ts
const middleware = expressAuth(auth, {
  errorFormatter: (error) => ({
    status: error.status,
    body: { error: { code: error.code, message: error.message } },
  }),
});
app.use(middleware.errorHandler()); // Mount after routes.
```

The formatter receives only a public projection (`status`, `code`, `message`), not the original exception, stack, cause, or developer message. Unknown failures become a generic 500. Applications can pass another formatter to `errorHandler(formatter)`. Do not include passwords, token values, secrets, database errors, stack traces, or other internal details in custom responses.
