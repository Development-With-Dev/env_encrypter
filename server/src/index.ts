import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import mongoose from 'mongoose';
import dotenv from 'dotenv';
import hpp from 'hpp';
import mongoSanitize from 'express-mongo-sanitize';
import secretsRouter from './routes/secrets';
import { globalLimiter } from './middleware/rateLimiter';
import {
  requestId,
  securityAuditLog,
  hardenedHeaders,
} from './middleware/security';
import { startCleanupService, stopCleanupService } from './utils/cleanup';

// Load environment variables
dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/secureenv';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';

// ─────────────────────────────────────────────────────────
// REQUEST ID (first, so all downstream middleware can reference it)
// ─────────────────────────────────────────────────────────
app.use(requestId);

// ─────────────────────────────────────────────────────────
// SECURITY HEADERS (Helmet)
// ─────────────────────────────────────────────────────────
/**
 * Helmet sets various HTTP headers to help protect the app:
 * - Content-Security-Policy: Restricts resource loading
 * - X-Content-Type-Options: Prevents MIME type sniffing
 * - X-Frame-Options: Prevents clickjacking
 * - Strict-Transport-Security: Enforces HTTPS
 * - Referrer-Policy: Prevents URL leakage
 * 
 * CRITICAL: referrerPolicy is set to "no-referrer" to prevent
 * the share URL (containing the encryption key in the fragment)
 * from leaking via the Referer header.
 */
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'", CORS_ORIGIN],
      },
    },
    referrerPolicy: { policy: 'no-referrer' },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true, // Enable HSTS preloading for browser lists
    },
  })
);

// ─────────────────────────────────────────────────────────
// HARDENED RESPONSE HEADERS (beyond Helmet)
// ─────────────────────────────────────────────────────────
app.use(hardenedHeaders);

// ─────────────────────────────────────────────────────────
// CORS
// ─────────────────────────────────────────────────────────
/**
 * Strict CORS configuration:
 * - Only the frontend origin is allowed
 * - Credentials disabled (no cookies needed for this stateless API)
 * - Limited allowed headers
 */
app.use(
  cors({
    origin: CORS_ORIGIN,
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type'],
    credentials: false,
    maxAge: 86400, // Cache preflight for 24h to reduce OPTIONS requests
  })
);

// ─────────────────────────────────────────────────────────
// BODY PARSING
// ─────────────────────────────────────────────────────────
/**
 * Limit JSON body to 100KB to prevent memory exhaustion attacks.
 * The encrypted .env data is capped at ~68KB (base64 of ~50KB),
 * plus metadata overhead.
 */
app.use(express.json({ limit: '100kb' }));

// ─────────────────────────────────────────────────────────
// HTTP PARAMETER POLLUTION PROTECTION
// ─────────────────────────────────────────────────────────
/**
 * hpp prevents HTTP Parameter Pollution attacks where attackers
 * send duplicate query/body parameters to confuse the application.
 * Example attack: ?token=real_token&token=evil_token
 * hpp ensures only the last value is used, preventing ambiguity.
 */
app.use(hpp());

// ─────────────────────────────────────────────────────────
// MONGODB QUERY INJECTION PROTECTION
// ─────────────────────────────────────────────────────────
/**
 * express-mongo-sanitize removes keys starting with '$' or containing '.'
 * from req.body, req.query, and req.params.
 *
 * Without this, an attacker could send:
 *   { "accessToken": { "$gt": "" } }
 * which would match ALL documents in a MongoDB query.
 *
 * With sanitization, the '$gt' key is stripped, preventing NoSQL injection.
 */
app.use(mongoSanitize());

// ─────────────────────────────────────────────────────────
// AUDIT LOGGING
// ─────────────────────────────────────────────────────────
app.use('/api/secrets', securityAuditLog);

// ─────────────────────────────────────────────────────────
// TRUST PROXY
// ─────────────────────────────────────────────────────────
/**
 * Required for rate limiting to work correctly behind reverse proxies
 * (Vercel, Render, Cloudflare, etc.). Without this, all requests
 * appear to come from the proxy's IP.
 */
app.set('trust proxy', 1);

// ─────────────────────────────────────────────────────────
// GLOBAL RATE LIMITER
// ─────────────────────────────────────────────────────────
app.use(globalLimiter);

// ─────────────────────────────────────────────────────────
// ROUTES
// ─────────────────────────────────────────────────────────
app.use('/api/secrets', secretsRouter);

// Health check endpoint (no rate limiting)
app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// ─────────────────────────────────────────────────────────
// 404 HANDLER
// ─────────────────────────────────────────────────────────
app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// ─────────────────────────────────────────────────────────
// GLOBAL ERROR HANDLER
// ─────────────────────────────────────────────────────────
/**
 * Catch-all error handler to prevent stack traces from leaking
 * to the client. In production, stack traces reveal internal
 * file paths and library versions — gold for attackers.
 */
app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('💥 Unhandled error:', err.message);

  // Never expose internal error details in production
  const isDev = process.env.NODE_ENV === 'development';
  res.status(500).json({
    error: 'Internal server error',
    ...(isDev && { detail: err.message }),
  });
});

// ─────────────────────────────────────────────────────────
// DATABASE CONNECTION + SERVER START
// ─────────────────────────────────────────────────────────
async function start() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    // Start the background cleanup service
    startCleanupService();

    const server = app.listen(PORT, () => {
      console.log(`🔒 SecureEnv API running on port ${PORT}`);
      console.log(`   CORS origin: ${CORS_ORIGIN}`);
      console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`   Security: Helmet + HPP + MongoSanitize + AuditLog + Cleanup`);
    });

    // ─────────────────────────────────────────────────────────
    // GRACEFUL SHUTDOWN
    // ─────────────────────────────────────────────────────────
    /**
     * On SIGTERM/SIGINT (container stop, Ctrl+C):
     * 1. Stop accepting new connections
     * 2. Stop the cleanup service
     * 3. Close the MongoDB connection
     * 4. Exit cleanly
     *
     * Without this, in-flight requests could be aborted mid-write,
     * and the cleanup interval keeps the process alive indefinitely.
     */
    const shutdown = async (signal: string) => {
      console.log(`\n🛑 ${signal} received. Starting graceful shutdown...`);
      stopCleanupService();

      server.close(async () => {
        console.log('   HTTP server closed');
        await mongoose.connection.close();
        console.log('   MongoDB connection closed');
        process.exit(0);
      });

      // Force kill after 10s if graceful shutdown hangs
      setTimeout(() => {
        console.error('   Forced shutdown after timeout');
        process.exit(1);
      }, 10000);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

start();

export default app;
