import { Router, Request, Response } from 'express';
import { Secret } from '../models/Secret';
import { generateAccessToken, hashIP } from '../utils/token';
import { validateCreateSecret, validateAccessToken } from '../middleware/validate';
import { createSecretLimiter, retrieveSecretLimiter } from '../middleware/rateLimiter';
import { abuseDetection, payloadIntegrityCheck } from '../middleware/security';

const router = Router();

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

      const accessToken = generateAccessToken();

      const clientIP =
        (req.headers['x-forwarded-for'] as string)?.split(',')[0]?.trim()
        || req.ip
        || 'unknown';
      const ipHash = hashIP(clientIP);

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
        res.status(404).json({ error: 'Secret not found or has expired' });
        return;
      }

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

router.get(
  '/:token',
  retrieveSecretLimiter,
  validateAccessToken,
  async (req: Request, res: Response): Promise<void> => {
    try {
      const { token } = req.params;

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
          new: true,
        }
      );

      if (!secret) {
        const exists = await Secret.findOne({ accessToken: token });
        if (exists) {
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

      if (secret.encryptedData === '[SCRUBBED]') {
        res.status(410).json({
          error: 'This secret has been permanently deleted.',
        });
        return;
      }

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
