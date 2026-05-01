/**
 * SecureEnv API Client
 * Interfaces with the Express backend.
 */

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:4000/api';

export interface SecretMetadata {
  isPasswordProtected: boolean;
  maxViews: number | null;
  viewsRemaining: number | null;
  expiresAt: string;
  createdAt?: string;
}

export interface SecretResponse {
  encryptedData: string;
  iv: string;
  salt?: string;
  isPasswordProtected: boolean;
  viewsRemaining: number | null;
  expiresAt: string;
}

export interface CreateSecretPayload {
  encryptedData: string;
  iv: string;
  salt?: string;
  isPasswordProtected: boolean;
  maxViews: number | null;
  expiresIn: number; // in seconds
}

export interface CreateSecretResponse {
  accessToken: string;
  expiresAt: string;
}

/**
 * Stores an encrypted secret on the server.
 */
export async function createSecret(payload: CreateSecretPayload): Promise<CreateSecretResponse> {
  const response = await fetch(`${API_BASE_URL}/secrets`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
    },
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to create secret');
  }

  return response.json();
}

/**
 * Retrieves an encrypted secret from the server.
 * This call increments the view count.
 */
export async function getSecret(token: string): Promise<SecretResponse> {
  const response = await fetch(`${API_BASE_URL}/secrets/${token}`);

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to retrieve secret');
  }

  return response.json();
}

/**
 * Retrieves metadata for a secret without incrementing the view count.
 */
export async function getSecretMetadata(token: string): Promise<SecretMetadata> {
  const response = await fetch(`${API_BASE_URL}/secrets/${token}/meta`);

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to retrieve metadata');
  }

  return response.json();
}

/**
 * Manually burns (deletes) a secret.
 */
export async function deleteSecret(token: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}/secrets/${token}`, {
    method: 'DELETE',
  });

  if (!response.ok) {
    const errorData = await response.json();
    throw new Error(errorData.error || 'Failed to delete secret');
  }
}
