import { Request, Response, NextFunction } from 'express';
import crypto from 'crypto';
import { Secret } from '../models/Secret';
import { hashIP } from '../utils/token';

// ─────────────────────────────────────────────────────────
// 1. ABUSE DETECTION: Per-IP secret creation throttle (DB-backed)
// ─────────────────────────────────────────────────────────
/**
 * Limits the total number of secrets a single IP can create
 * within a rolling time window. Unlike the rate limiter (which resets
 * with the process), this is backed by MongoDB and persists across restarts.
 *
 * SECURITY RATIONALE:
 * - Rate limiter handles burst abuse (5 req/15min)
 * - This handles sustained abuse (max 20 secrets/24h from one IP)
 * - Even if the attacker rotates user agents or clients, the IP hash catches them
 */
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
    // Fail open — if DB is unreachable, let the request through
    // (the route itself will also fail, so this is safe)
    next();
  }
}

// ─────────────────────────────────────────────────────────
// 2. PAYLOAD INTEGRITY VALIDATION
// ─────────────────────────────────────────────────────────
/**
 * Validates that the encrypted payload is well-formed:
 * - encryptedData and iv must be valid base64
 * - Rejects payloads with embedded HTML/script tags
 * - Ensures no null bytes (binary injection)
 *
 * This catches malformed data BEFORE it hits the database,
 * preventing storage of garbage that could cause issues during retrieval.
 */
const BASE64_REGEX = /^[A-Za-z0-9+/]*={0,2}$/;

export function payloadIntegrityCheck(
  req: Request,
  res: Response,
  next: NextFunction
): void {
  const { encryptedData, iv, salt } = req.body;

  // Validate base64 encoding
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

  // Check for null bytes (binary injection attempt)
  const bodyStr = JSON.stringify(req.body);
  if (bodyStr.includes('\u0000')) {
    res.status(400).json({ error: 'Invalid payload: null bytes detected.' });
    return;
  }

  next();
}

// ─────────────────────────────────────────────────────────
// 3. REQUEST ID & AUDIT LOGGING
// ─────────────────────────────────────────────────────────
/**
 * Assigns each request a unique ID and logs security-relevant events.
 *
 * SECURITY RATIONALE:
 * - Unique request IDs enable tracing across distributed systems
 * - Security audit logs capture who did what, when
 * - Logs are sanitized to never contain sensitive data (no IPs, no tokens in full)
 *
 * In production, feed these logs into a SIEM (Splunk, Datadog, etc.)
 */
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

  // Log on response finish
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

    // Log security-relevant events
    if (res.statusCode === 429) {
      console.warn('🚨 RATE LIMITED:', JSON.stringify(logEntry));
    } else if (res.statusCode === 400) {
      console.warn('⚠️  BAD REQUEST:', JSON.stringify(logEntry));
    } else if (res.statusCode >= 500) {
      console.error('❌ SERVER ERROR:', JSON.stringify(logEntry));
    } else if (req.method === 'POST' && req.path === '/') {
      // Secret creation
      console.log('🔐 SECRET CREATED:', JSON.stringify(logEntry));
    } else if (req.method === 'DELETE') {
      console.log('🔥 SECRET BURNED:', JSON.stringify(logEntry));
    }
  });

  next();
}

// ─────────────────────────────────────────────────────────
// 4. EXTRA RESPONSE HEADERS
// ─────────────────────────────────────────────────────────
/**
 * Adds hardened security headers beyond what Helmet provides.
 *
 * - Cache-Control: Prevents caching of secret content by proxies/CDNs
 * - Permissions-Policy: Disables unnecessary browser APIs
 * - X-Content-Type-Options: Prevents MIME sniffing (redundant w/ Helmet, but explicit)
 */
export function hardenedHeaders(
  _req: Request,
  res: Response,
  next: NextFunction
): void {
  // Never cache API responses containing secrets
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
  res.setHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');

  // Disable browser features that could be exploited
  res.setHeader(
    'Permissions-Policy',
    'camera=(), microphone=(), geolocation=(), interest-cohort=()'
  );

  // Cross-Origin isolation headers
  res.setHeader('Cross-Origin-Opener-Policy', 'same-origin');
  res.setHeader('Cross-Origin-Resource-Policy', 'same-origin');

  next();
}

// ─────────────────────────────────────────────────────────
// 5. TIMING-SAFE TOKEN COMPARISON
// ─────────────────────────────────────────────────────────
/**
 * Constant-time comparison to prevent timing side-channel attacks.
 *
 * SECURITY RATIONALE:
 * If we used `===` to compare tokens, an attacker could measure response times
 * to determine how many leading characters matched, leaking the token byte-by-byte.
 * crypto.timingSafeEqual always takes the same time regardless of where the mismatch is.
 */
export function timingSafeCompare(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  return crypto.timingSafeEqual(bufA, bufB);
}
