import { Secret } from '../models/Secret';

const CLEANUP_INTERVAL_MS = 5 * 60 * 1000;

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

async function purgeOldBurnedSecrets(): Promise<number> {
  const oneHourAgo = new Date(Date.now() - 60 * 60 * 1000);
  const result = await Secret.deleteMany({
    burnedAt: { $ne: null, $lte: oneHourAgo },
  });
  return result.deletedCount;
}

async function runCleanup(): Promise<void> {
  try {
    const [scrubbed, burned, purged] = await Promise.all([
      scrubBurnedSecrets(),
      burnExhaustedSecrets(),
      purgeOldBurnedSecrets(),
    ]);

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

export function startCleanupService(): void {
  runCleanup();

  cleanupInterval = setInterval(runCleanup, CLEANUP_INTERVAL_MS);
  console.log('🧹 Cleanup service started (every 5 minutes)');
}

export function stopCleanupService(): void {
  if (cleanupInterval) {
    clearInterval(cleanupInterval);
    cleanupInterval = null;
    console.log('🧹 Cleanup service stopped');
  }
}
