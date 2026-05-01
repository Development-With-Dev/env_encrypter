import crypto from 'crypto';

/**
 * Generate a cryptographically secure access token.
 *
 * SECURITY RATIONALE:
 * - 32 bytes = 256 bits of entropy
 * - Hex encoding = 64 character string
 * - At 1 billion guesses/second, brute-force would take ~3.67 × 10^59 years
 * - Uses Node.js crypto.randomBytes which draws from the OS CSPRNG
 *
 * This token is used as the public identifier in share URLs.
 * It is NOT the encryption key — that lives only in the URL fragment.
 */
export function generateAccessToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Hash an IP address using SHA-256 for rate limiting.
 *
 * PRIVACY RATIONALE:
 * - We need to rate-limit by IP but don't want to store raw IPs
 * - SHA-256 is a one-way function — we can compare hashes but can't recover the IP
 * - No salt is used intentionally: we need deterministic hashes to count
 *   requests from the same IP across multiple requests
 *
 * NOTE: This is NOT for password hashing (use bcrypt/argon2 for that).
 * For IP rate limiting, SHA-256 is sufficient because:
 * 1. IPs are semi-public information
 * 2. We only need collision resistance, not preimage resistance against targeted attacks
 */
export function hashIP(ip: string): string {
  return crypto.createHash('sha256').update(ip).digest('hex');
}
