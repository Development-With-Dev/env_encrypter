import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Secret } from '../models/Secret';
import { hashIP } from '../utils/token';

const MAX_SECRETS_PER_IP_PER_DAY = 20;

export async function abuseDetection(
  req: Request,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const clientIP =
      (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
      || req.ip
      || 'unknown';
    const ipHash = hashIP(clientIP);

    const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);
    const secretCount = await Secret.countDocuments({
      ipHash,
      createdAt: { $gte: oneDayAgo },
    });

    if (secretCount >= MAX_SECRETS_PER_IP_PER_DAY) {
      res.status(429).json({
        error: 'Daily secret creation limit reached. Please try again tomorrow.',
        retryAfter: '24 hours',
      });
      return;
    }

    next();
  } catch (error) {
    next();
  }
}

const BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;

export function payloadIntegrityCheck(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const { encryptedData, iv, salt } = req.body;

  if (encryptedData && !BASE64_REGEX.test(encryptedData)) {
    res.status(400).json({
      error: 'Invalid encrypted data format. Must be valid base64.',
    });
    return;
  }

  if (iv && !BASE64_REGEX.test(iv)) {
    res.status(400).json({
      error: 'Invalid IV format. Must be valid base64.',
    });
    return;
  }

  if (salt && !BASE64_REGEX.test(salt)) {
    res.status(400).json({
      error: 'Invalid salt format. Must be valid base64.',
    });
    return;
  }

  const bodyStr = JSON.stringify(req.body);
  if (bodyStr.includes('\u0000')) {
    res.status(400).json({ error: 'Invalid payload: null bytes detected.' });
    return;
  }

  next();
}

export function requestId(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const id = crypto.randomUUID();
  req.headers['x-request-id'] = id;
  res.setHeader('X-Request-Id', id);
  next();
}

export function securityAuditLog(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const startTime = Date.now();
  const requestId = req.headers['x-request-id'] || 'unknown';

  res.on('finish', () => {
    const duration = Date.now() - startTime;
    const logEntry = {
      requestId,
      method: req.method,
      path: req.path,
      status: res.statusCode,
      duration: `${duration}ms`,
      userAgent: req.headers['user-agent']?.substring(0, 100) || 'unknown',
      timestamp: new Date().toISOString(),
    };

    if (res.statusCode === 429) {
      console.warn('🚨 RATE LIMITED:', JSON.stringify(logEntry));
    } else if (res.statusCode === 400) {
      console.warn('⚠️  BAD REQUEST:', JSON.stringify(logEntry));
    } else if (res.statusCode >= 500) {
      console.error('❌ SERVER ERROR:', JSON.stringify(logEntry));
    } else if (req.method === 'POST' && req.path === '/') {
      console.log('🔐 SECRET CREATED:', JSON.stringify(logEntry));
    } else if (req.method === 'DELETE') {
      console.log('🔥 SECRET BURNED:', JSON.stringify(logEntry));
    }
  });

  next();
}

export function hardenedHeaders(
  _req: Request,
  res: Response,
  next: NextFunction
): void {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), interest-cohort=()'
  );

  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  next();
}

export function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return crypto.timingSafeEqual(bufA, bufB);
}
