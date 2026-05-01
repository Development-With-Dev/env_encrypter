/**
 * SecureEnv Cryptography Utilities
 * Uses Web Crypto API for zero-knowledge end-to-end encryption.
 * Encryption: AES-256-GCM
 */

/**
 * Encodes a buffer to a base64 string.
 */
export function bufferToBase64(buffer: ArrayBuffer): string {
  return btoa(String.fromCharCode(...new Uint8Array(buffer)));
}

/**
 * Decodes a base64 string to a buffer.
 */
export function base64ToBuffer(base64: string): ArrayBuffer {
  const binaryString = atob(base64);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer;
}

/**
 * Generates a random 256-bit AES key.
 */
export async function generateEncryptionKey(): Promise<CryptoKey> {
  return await window.crypto.subtle.generateKey(
    {
      name: 'AES-GCM',
      length: 256,
    },
    true, // extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Exports a CryptoKey to a base64 string.
 */
export async function exportKey(key: CryptoKey): Promise<string> {
  const exported = await window.crypto.subtle.exportKey('raw', key);
  return bufferToBase64(exported);
}

/**
 * Imports a CryptoKey from a base64 string.
 */
export async function importKey(keyBase64: string): Promise<CryptoKey> {
  const buffer = base64ToBuffer(keyBase64);
  return await window.crypto.subtle.importKey(
    'raw',
    buffer,
    'AES-GCM',
    true,
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Returns the base64 encoded ciphertext and IV.
 */
export async function encryptData(
  plaintext: string,
  key: CryptoKey
): Promise<{ encryptedData: string; iv: string }> {
  const encoder = new TextEncoder();
  const data = encoder.encode(plaintext);
  
  // 12-byte IV is standard for GCM
  const iv = window.crypto.getRandomValues(new Uint8Array(12));
  
  const ciphertext = await window.crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv,
    },
    key,
    data
  );

  return {
    encryptedData: bufferToBase64(ciphertext),
    iv: bufferToBase64(iv.buffer),
  };
}

/**
 * Decrypts a base64 encoded ciphertext using AES-256-GCM.
 * Returns the plaintext string.
 */
export async function decryptData(
  encryptedDataBase64: string,
  ivBase64: string,
  key: CryptoKey
): Promise<string> {
  const ciphertext = base64ToBuffer(encryptedDataBase64);
  const iv = base64ToBuffer(ivBase64);
  
  try {
    const decrypted = await window.crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: new Uint8Array(iv),
      },
      key,
      ciphertext
    );

    const decoder = new TextDecoder();
    return decoder.decode(decrypted);
  } catch (error) {
    console.error('Decryption failed:', error);
    throw new Error('Failed to decrypt. The key might be incorrect.');
  }
}
