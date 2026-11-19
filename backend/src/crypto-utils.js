/**
 * crypto-utils.js — AES-256-CBC encrypt/decrypt for IMAP passwords (F-04)
 * Key: IMAP_ENCRYPT_KEY env var (64 hex chars = 32 bytes)
 *      fallback: SHA-256 of SECRET to get 32 bytes
 */
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

function getKey() {
  const hexKey = process.env.IMAP_ENCRYPT_KEY;
  if (hexKey && hexKey.length === 64) {
    return Buffer.from(hexKey, 'hex');
  }
  // Derive 32-byte key from SECRET
  const secret = process.env.SECRET || 'mr10x-default-secret';
  return createHash('sha256').update(secret).digest();
}

/**
 * Encrypt plaintext password → "iv:ciphertext" (both hex)
 */
export function encryptPassword(plaintext) {
  const key = getKey();
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  const encrypted = Buffer.concat([
    cipher.update(String(plaintext), 'utf8'),
    cipher.final()
  ]);
  return `${iv.toString('hex')}:${encrypted.toString('hex')}`;
}

/**
 * Decrypt "iv:ciphertext" → plaintext password
 * Returns the input unchanged if it doesn't look like our format (legacy plaintext)
 */
export function decryptPassword(stored) {
  if (!stored || !stored.includes(':')) return stored; // legacy plaintext — pass through
  const colonIdx = stored.indexOf(':');
  const ivHex  = stored.slice(0, colonIdx);
  const ctHex  = stored.slice(colonIdx + 1);
  if (ivHex.length !== 32) return stored; // not our format
  try {
    const key = getKey();
    const iv  = Buffer.from(ivHex, 'hex');
    const ct  = Buffer.from(ctHex, 'hex');
    const decipher = createDecipheriv('aes-256-cbc', key, iv);
    return Buffer.concat([decipher.update(ct), decipher.final()]).toString('utf8');
  } catch {
    return stored; // decryption failed — return raw (old data safety net)
  }
}
