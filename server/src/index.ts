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

dotenv.config();

const app = express();
const PORT = process.env.PORT || 4000;
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/secureenv';
const CORS_ORIGIN = process.env.CORS_ORIGIN || 'http://localhost:3000';

app.use(requestId);

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
      preload: true,
    },
  })
);

app.use(hardenedHeaders);

app.use(
  cors({
    origin: CORS_ORIGIN,
    methods: ['GET', 'POST', 'DELETE'],
    allowedHeaders: ['Content-Type'],
    credentials: false,
    maxAge: 86400,
  })
);

app.use(express.json({ limit: '100kb' }));

app.use(hpp());

app.use(mongoSanitize());

app.use('/api/secrets', securityAuditLog);

app.set('trust proxy', 1);

app.use(globalLimiter);

app.use('/api/secrets', secretsRouter);

app.get('/api/health', (_req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

app.use((_req, res) => {
  res.status(404).json({ error: 'Not found' });
});

app.use((err: Error, _req: express.Request, res: express.Response, _next: express.NextFunction) => {
  console.error('💥 Unhandled error:', err.message);

  const isDev = process.env.NODE_ENV === 'development';
  res.status(500).json({
    error: 'Internal server error',
    ...(isDev && { detail: err.message }),
  });
});

async function start() {
  try {
    await mongoose.connect(MONGODB_URI);
    console.log('✅ Connected to MongoDB');

    startCleanupService();

    const server = app.listen(PORT, () => {
      console.log(`🔒 SecureEnv API running on port ${PORT}`);
      console.log(`   CORS origin: ${CORS_ORIGIN}`);
      console.log(`   Environment: ${process.env.NODE_ENV || 'development'}`);
      console.log(`   Security: Helmet + HPP + MongoSanitize + AuditLog + Cleanup`);
    });

    const shutdown = async (signal: string) => {
      console.log(`\n🛑 ${signal} received. Starting graceful shutdown...`);
      stopCleanupService();

      server.close(async () => {
        console.log('   HTTP server closed');
        await mongoose.connection.close();
        console.log('   MongoDB connection closed');
        process.exit(0);
      });

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
