import { Router, Request, Response } from 'express';
import { Secret } from '../models/Secret';
import { generateAccessToken, hashIP } from '../utils/token';
import { validateCreateSecret, validateAccessToken } from '../middleware/validate';
import { createSecretLimiter, retrieveSecretLimiter } from '../middleware/rateLimiter';
import { abuseDetection, payloadIntegrityCheck } from '../middleware/security';

const router = Router();

/**
 * POST /api/secrets
 * 
 * Store an encrypted secret. The server receives ONLY:
 * - Encrypted ciphertext (AES-256-GCM output)
 * - IV (initialization vector)
 * - Salt (if password-protected)
 * - Metadata (maxViews, expiresIn, isPasswordProtected)
 * 
 * The server NEVER receives:
 * - The plaintext .env content
 * - The encryption key
 * - The user's password (if any)
 * 
 * SECURITY: The encrypted data is opaque bytes to the server.
 * Even a compromised server cannot decrypt the content.
 * 
 * MIDDLEWARE CHAIN:
 * 1. createSecretLimiter  — burst rate limit (5/15min)
 * 2. validateCreateSecret — schema validation (express-validator)
 * 3. payloadIntegrityCheck — base64 & injection checks
 * 4. abuseDetection       — daily IP limit (20/day, DB-backed)
 */
router.post(
  '/',
  createSecretLimiter,
  validateCreateSecret,
  payloadIntegrityCheck,
  abuseDetection,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const {
        encryptedData,
        iv,
        salt,
        isPasswordProtected,
        maxViews,
        expiresIn,
      } = req.body;

      // Generate a cryptographically random access token for the share URL
      const accessToken = generateAccessToken();

      // Hash the client IP for rate-limiting queries (privacy-preserving)
      const clientIP =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
        || req.ip
        || 'unknown';
      const ipHash = hashIP(clientIP);

      // Calculate absolute expiration timestamp
      const expiresAt = new Date(Date.now() + expiresIn * 1000);

      const secret = new Secret({
        accessToken,
        encryptedData,
        iv,
        salt: isPasswordProtected ? salt : undefined,
        isPasswordProtected: !!isPasswordProtected,
        maxViews: maxViews ?? null,
        currentViews: 0,
        expiresAt,
        ipHash,
      });

      await secret.save();

      res.status(201).json({
        accessToken,
        expiresAt: expiresAt.toISOString(),
      });
    } catch (error) {
      console.error('Failed to create secret:', error);
      res.status(500).json({ error: 'Failed to store secret' });
    }
  }
);

/**
 * GET /api/secrets/:token/meta
 * 
 * Retrieve metadata about a secret WITHOUT consuming a view.
 * Used by the frontend to show "views remaining" and "expires at"
 * before the user commits to viewing the secret.
 */
router.get(
  '/:token/meta',
  retrieveSecretLimiter,
  validateAccessToken,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { token } = req.params;

      const secret = await Secret.findOne({
        accessToken: token,
        burnedAt: null,
      }).select('isPasswordProtected maxViews currentViews expiresAt createdAt');

      if (!secret) {
        // Intentionally vague — don't reveal whether the token ever existed
        res.status(404).json({ error: 'Secret not found or has expired' });
        return;
      }

      // Check if views are exhausted
      if (secret.maxViews !== null && secret.currentViews >= secret.maxViews) {
        res.status(410).json({ error: 'Secret has been burned (max views reached)' });
        return;
      }

      res.json({
        isPasswordProtected: secret.isPasswordProtected,
        maxViews: secret.maxViews,
        viewsRemaining:
          secret.maxViews !== null
            ? secret.maxViews - secret.currentViews
            : null,
        expiresAt: secret.expiresAt.toISOString(),
        createdAt: secret.createdAt.toISOString(),
      });
    } catch (error) {
      console.error('Failed to get secret metadata:', error);
      res.status(500).json({ error: 'Failed to retrieve metadata' });
    }
  }
);

/**
 * GET /api/secrets/:token
 * 
 * Retrieve the encrypted secret data.
 * 
 * CRITICAL SECURITY: This endpoint uses findOneAndUpdate with $inc
 * to ATOMICALLY increment the view counter. This prevents a race condition
 * where two simultaneous requests could both read currentViews=0 and both
 * succeed, effectively giving 2 views on a maxViews=1 secret.
 * 
 * The atomic operation ensures that even under concurrent access,
 * the view count is always accurate.
 */
router.get(
  '/:token',
  retrieveSecretLimiter,
  validateAccessToken,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { token } = req.params;

      /**
       * ATOMIC OPERATION:
       * 1. Find the document where:
       *    - accessToken matches
       *    - Not yet burned
       *    - Either no maxViews limit, OR currentViews < maxViews
       * 2. Increment currentViews by 1
       * 3. Return the updated document
       * 
       * If no document matches (expired, burned, or views exhausted),
       * the operation returns null — no partial update occurs.
       */
      const secret = await Secret.findOneAndUpdate(
        {
          accessToken: token,
          burnedAt: null,
          $or: [
            { maxViews: null },
            { $expr: { $lt: ['$currentViews', '$maxViews'] } },
          ],
        },
        {
          $inc: { currentViews: 1 },
        },
        {
          new: true, // Return the document AFTER the update
        }
      );

      if (!secret) {
        // Distinguish between "never existed" and "burned/expired"
        const exists = await Secret.findOne({ accessToken: token });
        if (exists) {
          // Mark as burned if views exhausted
          if (
            exists.maxViews !== null &&
            exists.currentViews >= exists.maxViews
          ) {
            if (!exists.burnedAt) {
              await Secret.updateOne(
                { accessToken: token },
                { $set: { burnedAt: new Date() } }
              );
            }
            res.status(410).json({
              error: 'This secret has been burned. It can no longer be accessed.',
            });
            return;
          }
          // Burned manually
          if (exists.burnedAt) {
            res.status(410).json({
              error: 'This secret has been permanently deleted.',
            });
            return;
          }
        }
        res.status(404).json({ error: 'Secret not found or has expired' });
        return;
      }

      // Check if the secret data was already scrubbed by the cleanup service
      if (secret.encryptedData === '[SCRUBBED]') {
        res.status(410).json({
          error: 'This secret has been permanently deleted.',
        });
        return;
      }

      /**
       * AUTO-BURN: If this view was the last allowed view,
       * mark the secret as burned for clarity.
       * The TTL index will eventually clean it up, but we mark it
       * immediately so subsequent requests get a clear 410 response.
       */
      if (
        secret.maxViews !== null &&
        secret.currentViews >= secret.maxViews
      ) {
        await Secret.updateOne(
          { accessToken: token },
          { $set: { burnedAt: new Date() } }
        );
      }

      res.json({
        encryptedData: secret.encryptedData,
        iv: secret.iv,
        salt: secret.salt || undefined,
        isPasswordProtected: secret.isPasswordProtected,
        viewsRemaining:
          secret.maxViews !== null
            ? secret.maxViews - secret.currentViews
            : null,
        expiresAt: secret.expiresAt.toISOString(),
      });
    } catch (error) {
      console.error('Failed to retrieve secret:', error);
      res.status(500).json({ error: 'Failed to retrieve secret' });
    }
  }
);

/**
 * DELETE /api/secrets/:token
 * 
 * Manually burn (permanently delete) a secret.
 * This is a "burn after reading" action — once burned, the encrypted
 * data is immediately removed from the database.
 * 
 * NOTE: In a production system, you might want to require proof of
 * ownership (e.g., a burn token generated at creation time) to prevent
 * anyone with the share link from deleting the secret. For this MVP,
 * we allow anyone with the access token to burn the secret, which is
 * acceptable because:
 * 1. The access token is 256 bits of entropy (unguessable)
 * 2. Anyone with the token could read the secret anyway
 */
router.delete(
  '/:token',
  retrieveSecretLimiter,
  validateAccessToken,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { token } = req.params;

      const result = await Secret.findOneAndDelete({ accessToken: token });

      if (!result) {
        res.status(404).json({ error: 'Secret not found or already deleted' });
        return;
      }

      res.json({ message: 'Secret permanently deleted' });
    } catch (error) {
      console.error('Failed to delete secret:', error);
      res.status(500).json({ error: 'Failed to delete secret' });
    }
  }
);

export default router;
