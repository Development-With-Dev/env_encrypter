import mongoose, { Schema, Document } from 'mongoose';

export interface ISecret extends Document {
  accessToken: string;
  encryptedData: string;
  iv: string;
  salt?: string;
  isPasswordProtected: boolean;
  maxViews: number | null;
  currentViews: number;
  expiresAt: Date;
  createdAt: Date;
  ipHash: string;
  burnedAt?: Date;
}

const SecretSchema = new Schema<ISecret>(
  {
    accessToken: {
      type: String,
      required: true,
      unique: true,
      index: true,
      match: /^[a-f0-9]{64}$/,
    },

    encryptedData: {
      type: String,
      required: true,
      maxlength: 68_000,
    },

    iv: {
      type: String,
      required: true,
      maxlength: 24,
    },

    salt: {
      type: String,
      required: false,
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
    versionKey: false,
  }
);

SecretSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });

SecretSchema.index({ ipHash: 1, createdAt: 1 });

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
