import crypto from 'crypto';

export function generateAccessToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

export function hashIP(ip: string): string {
  return crypto.createHash('sha256').update(ip).digest('hex');
}
