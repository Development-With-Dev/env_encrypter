# 🔒 Backend Security Enhancements

All changes compile cleanly with zero TypeScript errors.

## New Files Created

| File | Purpose |
|------|---------|
| [security.ts](file:///g:/RENDER/server/src/middleware/security.ts) | 5 new security middleware functions |
| [cleanup.ts](file:///g:/RENDER/server/src/utils/cleanup.ts) | Background data scrubbing service |

## Modified Files

| File | Changes |
|------|---------|
| [index.ts](file:///g:/RENDER/server/src/index.ts) | Wired all middleware, added error handler & graceful shutdown |
| [secrets.ts](file:///g:/RENDER/server/src/routes/secrets.ts) | Added integrity + abuse middleware to POST route |

---

## Security Features Added

### 1. NoSQL Injection Protection (`express-mongo-sanitize`)
Strips `$` and `.` operators from request bodies/params. Without this, an attacker could send `{ "accessToken": { "$gt": "" } }` to match **all** documents.

### 2. HTTP Parameter Pollution Protection (`hpp`)
Prevents duplicate parameter attacks like `?token=real&token=evil`. Ensures unambiguous parameter resolution.

### 3. Payload Integrity Validation
Validates that `encryptedData`, `iv`, and `salt` are **valid base64** before reaching the database. Also rejects payloads with null bytes (binary injection).

### 4. IP-Based Abuse Detection (DB-backed)
Limits each IP to **20 secrets per 24 hours** via MongoDB queries. Unlike the in-memory rate limiter (which resets on restart), this persists across server restarts.

### 5. Security Audit Logging
Logs security-relevant events with unique request IDs:
- 🚨 Rate-limited requests (429)
- ⚠️ Bad requests (400)
- ❌ Server errors (500)
- 🔐 Secret creations
- 🔥 Secret burns/deletes

### 6. Hardened Response Headers
Beyond Helmet's defaults:
- `Cache-Control: no-store` — prevents proxy/CDN caching of secrets
- `Permissions-Policy` — disables camera, microphone, geolocation, FLoC
- `Cross-Origin-Opener-Policy: same-origin` — cross-origin isolation
- `Cross-Origin-Resource-Policy: same-origin` — blocks cross-origin reads
- `HSTS preload` — enables browser HSTS preload list inclusion

### 7. Background Cleanup Service (every 5 min)
Three-phase cleanup:
1. **Scrub** burned secrets — replaces ciphertext with `[SCRUBBED]` immediately
2. **Force-burn** exhausted secrets — catches edge cases where burn flag was missed
3. **Purge** old burned secrets — deletes burned documents after 1 hour

### 8. Global Error Handler
Catches unhandled errors and prevents **stack trace leakage** to clients. In production, only returns `"Internal server error"`.

### 9. Graceful Shutdown
On `SIGTERM`/`SIGINT`:
1. Stops the cleanup service interval
2. Closes the HTTP server (drains in-flight requests)
3. Closes the MongoDB connection
4. 10-second forced-kill timeout as safety net

### 10. Request ID Tracking
Every request gets a `X-Request-Id` UUID header, enabling distributed tracing and log correlation.

---

## New Dependencies

| Package | Purpose |
|---------|---------|
| `hpp` | HTTP Parameter Pollution protection |
| `express-mongo-sanitize` | NoSQL injection prevention |
| `@types/hpp` | TypeScript declarations for hpp |

## Security Middleware Pipeline (POST /api/secrets)

```
Request → requestId → helmet → hardenedHeaders → cors → json(100kb)
       → hpp → mongoSanitize → auditLog → globalLimiter
       → createSecretLimiter → validateCreateSecret
       → payloadIntegrityCheck → abuseDetection → handler
```
