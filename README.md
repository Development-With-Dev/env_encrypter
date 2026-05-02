# SecureEnv

A zero-knowledge, end-to-end encrypted `.env` file sharing service. SecureEnv allows developers to securely share environment variables and configuration secrets through ephemeral, self-destructing links without ever exposing plaintext data to the server.

---

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Security Model](#security-model)
- [Tech Stack](#tech-stack)
- [Project Structure](#project-structure)
- [Getting Started](#getting-started)
- [Environment Variables](#environment-variables)
- [API Reference](#api-reference)
- [Deployment](#deployment)
- [License](#license)

---

## Overview

SecureEnv solves the problem of sharing sensitive configuration data between team members. Instead of sending `.env` files over Slack, email, or other insecure channels, SecureEnv encrypts the data entirely in the browser before it ever reaches the server.

The server stores only opaque ciphertext. The encryption key is embedded in the URL fragment (`#`), which browsers never transmit to the server per RFC 3986. Even a fully compromised server cannot decrypt the stored secrets.

---

## Architecture

```
Client (Browser)                         Server (Express + MongoDB)
---------------------                    ----------------------------
                                         
1. User pastes .env content              
2. AES-256-GCM encryption (Web Crypto)   
3. Key stored in URL fragment (#)        
4. Ciphertext + IV sent to server  --->  5. Stores encrypted blob + metadata
                                         6. Returns access token
7. Share link = /secret/{token}#{key}    
                                         
--- Recipient Flow ---                   
                                         
8. Recipient opens link                  
9. Browser extracts key from fragment    
10. Fetches ciphertext from server <---  11. Returns encrypted data, increments view count
12. Decrypts locally in browser          
13. Plaintext displayed (never leaves browser)
```

The server never has access to the plaintext content, the encryption key, or the user's optional password.

---

## Security Model

### Encryption

- **Algorithm**: AES-256-GCM via the Web Crypto API
- **Key Size**: 256-bit randomly generated per secret
- **IV**: 12-byte cryptographically random initialization vector
- **Key Transport**: URL fragment (never sent to server)

### Server-Side Protections

| Layer | Implementation |
|-------|---------------|
| Rate Limiting | Per-IP burst limits (express-rate-limit) and daily DB-backed abuse detection |
| Input Validation | Schema validation via express-validator with base64 integrity checks |
| NoSQL Injection | Query sanitization via express-mongo-sanitize |
| HTTP Parameter Pollution | Duplicate parameter protection via hpp |
| Security Headers | Helmet with strict CSP, HSTS preloading, no-referrer policy |
| Cache Prevention | `no-store, no-cache` headers on all API responses |
| Timing Attacks | Constant-time token comparison via `crypto.timingSafeEqual` |
| IP Privacy | SHA-256 hashed IPs for rate limiting (raw IPs never stored) |

### Data Lifecycle

- **Self-Destruct**: Secrets auto-burn after a configurable view limit (1-100 views)
- **TTL Expiration**: MongoDB TTL index auto-deletes expired documents
- **Proactive Cleanup**: Background service scrubs burned secrets every 5 minutes
- **Immediate Scrub**: Ciphertext is replaced with `[SCRUBBED]` on burn, before TTL deletion

---

## Tech Stack

### Server

| Technology | Purpose |
|-----------|---------|
| Node.js + Express | HTTP API |
| TypeScript | Type safety |
| MongoDB + Mongoose | Data persistence with TTL indexes |
| Helmet | Security headers |
| express-rate-limit | Rate limiting |
| express-validator | Request validation |
| express-mongo-sanitize | NoSQL injection prevention |
| hpp | HTTP parameter pollution protection |

### Client

| Technology | Purpose |
|-----------|---------|
| Next.js 16 | React framework with server components |
| React 19 | UI library |
| TypeScript | Type safety |
| Tailwind CSS 4 | Styling |
| Web Crypto API | Client-side AES-256-GCM encryption |

---

## Project Structure

```
.
├── server/
│   ├── src/
│   │   ├── index.ts                 # Express app setup and server bootstrap
│   │   ├── middleware/
│   │   │   ├── rateLimiter.ts       # Rate limiting (create, retrieve, global)
│   │   │   ├── security.ts          # Abuse detection, payload checks, audit logging
│   │   │   └── validate.ts          # Request validation schemas
│   │   ├── models/
│   │   │   └── Secret.ts            # Mongoose schema and indexes
│   │   ├── routes/
│   │   │   └── secrets.ts           # CRUD endpoints for secrets
│   │   └── utils/
│   │       ├── cleanup.ts           # Background cleanup service
│   │       └── token.ts             # Token generation and IP hashing
│   ├── .env.example
│   ├── package.json
│   └── tsconfig.json
├── client/
│   ├── src/
│   │   ├── app/
│   │   │   ├── globals.css          # Design system and theme
│   │   │   ├── layout.tsx           # Root layout
│   │   │   ├── page.tsx             # Home page with encryption form
│   │   │   └── secret/[id]/
│   │   │       └── page.tsx         # Secret viewer page
│   │   ├── components/
│   │   │   ├── EncryptForm.tsx      # Encryption form component
│   │   │   └── SecretViewer.tsx     # Decryption and viewing component
│   │   └── lib/
│   │       ├── api.ts               # API client functions
│   │       └── crypto.ts            # Web Crypto API utilities
│   ├── package.json
│   └── tsconfig.json
├── .gitignore
└── README.md
```

---

## Getting Started

### Prerequisites

- Node.js 18+
- MongoDB (local instance or MongoDB Atlas)

### 1. Clone the Repository

```bash
git clone https://github.com/Development-With-Dev/env_encrypter.git
cd env_encrypter
```

### 2. Set Up the Server

```bash
cd server
npm install
cp .env.example .env
```

Edit `.env` with your MongoDB connection string and desired configuration, then start the development server:

```bash
npm run dev
```

The API will be available at `http://localhost:4000`.

### 3. Set Up the Client

```bash
cd client
npm install
```

Create a `.env.local` file:

```
NEXT_PUBLIC_API_URL=http://localhost:4000/api
```

Start the development server:

```bash
npm run dev
```

The application will be available at `http://localhost:3000`.

---

## Environment Variables

### Server (`server/.env`)

| Variable | Default | Description |
|----------|---------|-------------|
| `MONGODB_URI` | `mongodb://localhost:27017/secureenv` | MongoDB connection string |
| `CORS_ORIGIN` | `http://localhost:3000` | Allowed frontend origin for CORS |
| `PORT` | `4000` | Server listening port |
| `NODE_ENV` | `development` | Environment mode |

### Client (`client/.env.local`)

| Variable | Default | Description |
|----------|---------|-------------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:4000/api` | Backend API base URL |

---

## API Reference

### Create Secret

```
POST /api/secrets
```

**Request Body:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `encryptedData` | string | Yes | Base64-encoded AES-256-GCM ciphertext |
| `iv` | string | Yes | Base64-encoded 12-byte initialization vector |
| `salt` | string | No | Base64-encoded PBKDF2 salt (password-protected secrets) |
| `isPasswordProtected` | boolean | Yes | Whether a password is required for decryption |
| `maxViews` | number | No | Maximum views before auto-burn (1-100, null for unlimited) |
| `expiresIn` | number | Yes | Time-to-live in seconds (300-604800) |

**Response (201):**

```json
{
  "accessToken": "a1b2c3...64-char-hex",
  "expiresAt": "2025-01-01T00:00:00.000Z"
}
```

### Get Secret Metadata

```
GET /api/secrets/:token/meta
```

Returns metadata without consuming a view.

**Response (200):**

```json
{
  "isPasswordProtected": false,
  "maxViews": 5,
  "viewsRemaining": 3,
  "expiresAt": "2025-01-01T00:00:00.000Z",
  "createdAt": "2024-12-31T00:00:00.000Z"
}
```

### Retrieve Secret

```
GET /api/secrets/:token
```

Returns the encrypted data and atomically increments the view counter.

**Response (200):**

```json
{
  "encryptedData": "base64...",
  "iv": "base64...",
  "salt": "base64...",
  "isPasswordProtected": false,
  "viewsRemaining": 2,
  "expiresAt": "2025-01-01T00:00:00.000Z"
}
```

### Delete Secret

```
DELETE /api/secrets/:token
```

Permanently deletes the secret from the database.

**Response (200):**

```json
{
  "message": "Secret permanently deleted"
}
```

### Error Responses

| Status | Meaning |
|--------|---------|
| 400 | Validation failed |
| 404 | Secret not found or expired |
| 410 | Secret has been burned (max views reached or manually deleted) |
| 429 | Rate limit exceeded |
| 500 | Internal server error |

---

## Deployment

### Server

Build and start the production server:

```bash
cd server
npm run build
npm start
```

Ensure the following for production:

- Set `NODE_ENV=production`
- Use a MongoDB Atlas connection string for `MONGODB_URI`
- Set `CORS_ORIGIN` to your deployed frontend URL
- Enable `trust proxy` if behind a reverse proxy (already configured)

### Client

Build the Next.js production bundle:

```bash
cd client
npm run build
npm start
```

Set `NEXT_PUBLIC_API_URL` to your deployed backend URL.

---

## License

This project is open source.
