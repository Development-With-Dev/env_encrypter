import rateLimit from 'express-rate-limit';

/**
 * Rate limiter for secret creation (POST /api/secrets).
 *
 * SECURITY RATIONALE:
 * - 5 secrets per 15 minutes per IP prevents abuse
 * - Uses IP-based limiting (works behind reverse proxies with trust proxy)
 * - Standard headers (RateLimit-*) inform clients of their remaining quota
 * - Legacy headers disabled to avoid confusion
 *
 * In production, consider using a Redis-backed store for distributed rate limiting.
 */
export const createSecretLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 5,                    // 5 creations per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many secrets created. Please try again later.',
    retryAfter: '15 minutes',
  },
  // Use the first IP from X-Forwarded-For (for Vercel/Render/Cloudflare)
  keyGenerator: (req) => {
    return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
      || req.ip
      || 'unknown';
  },
});

/**
 * Rate limiter for secret retrieval (GET /api/secrets/:token).
 *
 * More permissive than creation because:
 * 1. Retrieval is the primary user action
 * 2. Each retrieval already consumes a "view" (self-destruct counter)
 * 3. The 256-bit token makes enumeration infeasible
 *
 * However, we still limit to prevent DoS attacks.
 */
export const retrieveSecretLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,                   // 30 retrievals per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests. Please try again later.',
    retryAfter: '15 minutes',
  },
  keyGenerator: (req) => {
    return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
      || req.ip
      || 'unknown';
  },
});

/**
 * Global rate limiter applied to all routes.
 * Catches any abuse pattern not covered by route-specific limiters.
 */
export const globalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100,                  // 100 total requests per window
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Rate limit exceeded. Please try again later.',
    retryAfter: '15 minutes',
  },
  keyGenerator: (req) => {
    return (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
      || req.ip
      || 'unknown';
  },
});
