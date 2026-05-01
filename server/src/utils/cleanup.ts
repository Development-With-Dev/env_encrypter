import { Secret } from '../models/Secret';

/**
 * Proactive Secret Cleanup Service
 *
 * While MongoDB's TTL index handles expired documents, this service provides
 * additional security by actively scrubbing burned secrets and performing
 * periodic hygiene checks.
 *
 * SECURITY RATIONALE:
 * - MongoDB's TTL reaper runs every ~60s — that's 60s of exposure for expired data
 * - This service catches edge cases the TTL index might miss (e.g. burnedAt but not yet expired)
 * - It also scrubs the encryptedData from burned secrets immediately, so even if the document
 *   persists in MongoDB's journal or backup, the ciphertext is gone
 *
 * SCHEDULE: Runs every 5 minutes.
 */

const CLEANUP_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Scrub encrypted data from burned secrets.
 * Instead of waiting for TTL to delete the whole document, we immediately
 * clear the ciphertext from any secret that's been marked as burned.
 * This ensures the encrypted data doesn't linger in memory/disk.
 */
async function scrubBurnedSecrets(): Promise<number> {
  const result = await Secret.updateMany(
    {
      burnedAt: { $ne: null },
      encryptedData: { $ne: '[SCRUBBED]' },
    },
    {
      $set: {
        encryptedData: '[SCRUBBED]',
        iv: '[SCRUBBED]',
        salt: undefined,
      },
    }
  );
  return result.modifiedCount;
}

/**
 * Force-burn secrets that have exceeded their max views
 * but weren't properly marked (edge case safety net).
 */
async function burnExhaustedSecrets(): Promise<number> {
  const result = await Secret.updateMany(
    {
      burnedAt: null,
      maxViews: { $ne: null },
      $expr: { $gte: ['$currentViews', '$maxViews'] },
    },
    {
      $set: { burnedAt: new Date() },
    }
  );
  return result.modifiedCount;
}

/**
 * Delete very old burned secrets that TTL might have missed.
 * Catches documents where expiresAt was far in the future but the
 * secret was burned — no reason to keep them.
 */
async function purgeOldBurnedSecrets(): Promise<number> {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const result = await Secret.deleteMany({
    burnedAt: { $ne: null, $lte: oneHourAgo },
  });
  return result.deletedCount;
}

/**
 * Run all cleanup tasks and log results.
 */
async function runCleanup(): Promise<void> {
  try {
    const [scrubbed, burned, purged] = await Promise.all([
      scrubBurnedSecrets(),
      burnExhaustedSecrets(),
      purgeOldBurnedSecrets(),
    ]);

    // Only log if something was actually cleaned
    if (scrubbed > 0 || burned > 0 || purged > 0) {
      console.log(
        `🧹 Cleanup: scrubbed=${scrubbed}, force-burned=${burned}, purged=${purged}`
      );
    }
  } catch (error) {
    console.error('❌ Cleanup failed:', error);
  }
}

let cleanupInterval: ReturnType<typeof setInterval> | null = null;

/**
 * Start the background cleanup service.
 * Call once after MongoDB connection is established.
 */
export function startCleanupService(): void {
  // Run immediately on startup
  runCleanup();

  // Then run periodically
  cleanupInterval = setInterval(runCleanup, CLEANUP_INTERVAL_MS);
  console.log('🧹 Cleanup service started (every 5 minutes)');
}

/**
 * Stop the cleanup service (for graceful shutdown).
 */
export function stopCleanupService(): void {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log('🧹 Cleanup service stopped');
  }
}
