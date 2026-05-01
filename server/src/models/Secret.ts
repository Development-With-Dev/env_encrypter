import mongoose, { Schema, Document } from 'mongoose';

/**
 * Secret document interface.
 * 
 * SECURITY NOTE: This schema stores ONLY encrypted data.
 * The server NEVER has access to:
 *   - The plaintext .env content
 *   - The AES-256 encryption key
 *   - The user's optional password
 * 
 * The encryption key lives exclusively in the URL fragment (#)
 * which browsers never send to the server (RFC 3986 §3.5).
 */
export interface ISecret extends Document {
  /** Cryptographically random lookup token (hex, 32 bytes = 64 chars) */
  accessToken: string;

  /** Base64-encoded AES-256-GCM ciphertext */
  encryptedData: string;

  /** Base64-encoded 12-byte initialization vector */
  iv: string;

  /** Base64-encoded PBKDF2 salt (present only if password-protected) */
  salt?: string;

  /** Whether the secret requires a password to derive the decryption key */
  isPasswordProtected: boolean;

  /** Maximum allowed views before auto-burn (null = unlimited) */
  maxViews: number | null;

  /** Current view count (atomically incremented on each access) */
  currentViews: number;

  /** TTL expiration timestamp — MongoDB auto-deletes via TTL index */
  expiresAt: Date;

  /** Document creation timestamp */
  createdAt: Date;

  /** SHA-256 hash of creator's IP (for rate limiting, NOT tracking) */
  ipHash: string;

  /** Timestamp when the secret was burned (views exhausted or manual delete) */
  burnedAt?: Date;
}

const SecretSchema = new Schema<ISecret>(
  {
    accessToken: {
      type: String,
      required: true,
      unique: true,
      index: true,
      // 64 hex chars = 32 bytes of entropy = 256-bit security
      match: /^[a-f0-9]{64}$/,
    },

    encryptedData: {
      type: String,
      required: true,
      // Cap at ~68KB base64 ≈ ~50KB raw payload
      maxlength: 68_000,
    },

    iv: {
      type: String,
      required: true,
      // 12-byte IV → 16 chars base64
      maxlength: 24,
    },

    salt: {
      type: String,
      required: false,
      // 32-byte salt → 44 chars base64
      maxlength: 48,
    },

    isPasswordProtected: {
      type: Boolean,
      required: true,
      default: false,
    },

    maxViews: {
      type: Number,
      default: null,
      min: 1,
      max: 100,
    },

    currentViews: {
      type: Number,
      default: 0,
      min: 0,
    },

    expiresAt: {
      type: Date,
      required: true,
    },

    ipHash: {
      type: String,
      required: true,
      match: /^[a-f0-9]{64}$/,
    },

    burnedAt: {
      type: Date,
      default: null,
    },
  },
  {
    timestamps: { createdAt: true, updatedAt: false },
    // Strip __v from responses
    versionKey: false,
  }
);

/**
 * TTL INDEX: MongoDB automatically deletes documents when `expiresAt` passes.
 * The `expireAfterSeconds: 0` means "delete at the exact expiresAt timestamp".
 * MongoDB's TTL reaper runs every 60 seconds, so actual deletion may lag by ~60s.
 */
SecretSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

/**
 * Rate-limiting index: efficiently query secrets created by the same IP hash
 * within a time window.
 */
SecretSchema.index({ ipHash: 1, createdAt: 1 });

/**
 * SECURITY: Strip sensitive fields from JSON serialization.
 * Even though nothing here is truly "secret" (it's all encrypted),
 * we minimize the attack surface by not exposing internal fields.
 */
SecretSchema.set('toJSON', {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  transform: (_doc: any, ret: any) => {
    delete ret._id;
    delete ret.ipHash;
    delete ret.__v;
    return ret;
  },
});

export const Secret = mongoose.model<ISecret>('Secret', SecretSchema);
