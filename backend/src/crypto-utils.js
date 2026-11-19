/**
 * crypto-utils.js — AES-256-CBC encrypt/decrypt for IMAP passwords
 * Key: IMAP_ENCRYPT_KEY env var (required, 64 hex chars = 32 bytes)
 *
 * F-07: hardcoded fallback key removed. IMAP_ENCRYPT_KEY must be set in Railway
 * environment variables. Generate a key with:
 *   node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
 */
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';

function getKey() {
  const hexKey = process.env.IMAP_ENCRYPT_KEY;
  if (!hexKey || hexKey.length !== 64) {
    // F-07: fail fast — no silent fallback to a predictable key
    console.error('[FATAL] IMAP_ENCRYPT_KEY env var is missing or invalid (must be 64 hex chars = 32 bytes)');
    console.error('[FATAL] Generate one with: node -e "console.log(require(\'crypto\').randomBytes(32).toString(\'hex\'))"');
    process.exit(1);
  }
  return Buffer.from(hexKey, 'hex');
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
