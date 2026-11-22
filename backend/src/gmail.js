/**
 * gmail.js — Gmail OAuth2 + API helpers
 *
 * Flow:
 *   seller clicks "ربط Gmail" → GET /api/auth/gmail/start?mailbox_id=xxx (Bearer auth)
 *   → redirect to Google → callback GET /api/auth/gmail/callback?code=xxx&state=xxx
 *   → store tokens → redirect to dashboard
 *
 * Polling:
 *   every 60s, pollGmailMailboxes() loops over mailboxes with refresh_token,
 *   refreshes access token if needed, queries Gmail for messages newer than last_sync,
 *   extracts OTP codes, stores in codes table.
 */

import { createHmac, timingSafeEqual } from 'node:crypto';
import { extractCode } from './extract.js';
import { randomUUID } from 'node:crypto';
import { dbGet, dbAll, dbRun } from './db.js';

// ── Env helpers ───────────────────────────────────────────────────────────────
export function gmailEnabled() {
  return !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET && process.env.GOOGLE_REDIRECT_URI);
}

const GMAIL_SCOPES = [
  'https://www.googleapis.com/auth/gmail.readonly',
  'https://www.googleapis.com/auth/userinfo.email',
].join(' ');

// ── State signing ─────────────────────────────────────────────────────────────
const SECRET = () => process.env.SECRET || 'mr10x';

export function makeOAuthState(mailboxId, sellerId) {
  const ts = Date.now();
  const payload = `${mailboxId}:${sellerId}:${ts}`;
  const sig = createHmac('sha256', SECRET()).update(payload).digest('hex');
  return Buffer.from(JSON.stringify({ mailboxId, sellerId, ts, sig })).toString('base64url');
}

export function parseOAuthState(state) {
  try {
    const { mailboxId, sellerId, ts, sig } = JSON.parse(
      Buffer.from(state, 'base64url').toString('utf-8')
    );
    if (!mailboxId || !sellerId || !ts || !sig) return null;
    // expire after 10 minutes
    if (Date.now() - ts > 10 * 60 * 1000) return null;
    const payload = `${mailboxId}:${sellerId}:${ts}`;
    const expected = createHmac('sha256', SECRET()).update(payload).digest('hex');
    if (!timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
    return { mailboxId, sellerId };
  } catch {
    return null;
  }
}

// ── Auth URL ──────────────────────────────────────────────────────────────────
export function getAuthUrl(state) {
  const params = new URLSearchParams({
    client_id:     process.env.GOOGLE_CLIENT_ID,
    redirect_uri:  process.env.GOOGLE_REDIRECT_URI,
    response_type: 'code',
    scope:         GMAIL_SCOPES,
    access_type:   'offline',
    prompt:        'consent select_account',
    state,
  });
  return `https://accounts.google.com/o/oauth2/v2/auth?${params}`;
}

// ── Token exchange ────────────────────────────────────────────────────────────
export async function exchangeCode(code) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      code,
      client_id:     process.env.GOOGLE_CLIENT_ID,
      client_secret: process.env.GOOGLE_CLIENT_SECRET,
      redirect_uri:  process.env.GOOGLE_REDIRECT_URI,
      grant_type:    'authorization_code',
    }),
  });
  if (!r.ok) throw new Error(`exchangeCode: ${await r.text()}`);
  return r.json(); // { access_token, refresh_token, expires_in, token_type }
}

export async function refreshToken(refreshTok) {
  const r = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      refresh_token:  refreshTok,
      client_id:      process.env.GOOGLE_CLIENT_ID,
      client_secret:  process.env.GOOGLE_CLIENT_SECRET,
      grant_type:     'refresh_token',
    }),
  });
  if (!r.ok) throw new Error(`refreshToken: ${await r.text()}`);
  return r.json(); // { access_token, expires_in }
}

// Get the connected Gmail address
export async function getGmailAddress(accessToken) {
  const r = await fetch('https://www.googleapis.com/oauth2/v2/userinfo', {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!r.ok) return null;
  const d = await r.json();
  return d.email || null;
}

// ── Ensure fresh access token ─────────────────────────────────────────────────
/**
 * Returns a valid access_token for the mailbox.
 * Updates DB if token was refreshed.
 * Returns null if unable to refresh.
 */
export async function ensureFreshToken(mailbox) {
  const now = Math.floor(Date.now() / 1000);
  // If token is still valid for at least 5 more minutes, use it
  if (mailbox.gmail_access_token && mailbox.gmail_token_expiry > now + 300) {
    return mailbox.gmail_access_token;
  }
  // Need to refresh
  if (!mailbox.gmail_refresh_token) return null;
  try {
    const data = await refreshToken(mailbox.gmail_refresh_token);
    const expiry = now + (data.expires_in || 3600);
    await dbRun(`
      UPDATE mailboxes SET gmail_access_token = ?, gmail_token_expiry = ?, last_error = NULL
      WHERE id = ?
    `, [data.access_token, expiry, mailbox.id]);
    return data.access_token;
  } catch (err) {
    console.error(`[Gmail] token refresh failed for ${mailbox.email}:`, err.message);
    await dbRun(`UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?`,
      ['Gmail auth error — please reconnect', mailbox.id]);
    return null;
  }
}

// ── Gmail API: get new message IDs ────────────────────────────────────────────
/**
 * Returns up to 20 message IDs newer than `sinceTs` (unix seconds).
 */
async function listNewMessages(accessToken, sinceTs) {
  // Gmail search query: messages after a certain epoch second
  // "after:" accepts unix timestamps
  const q = sinceTs ? `after:${sinceTs}` : 'newer_than:5m';
  const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages?q=${encodeURIComponent(q)}&maxResults=20`;
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!r.ok) throw new Error(`listMessages: ${await r.text()}`);
  const data = await r.json();
  return data.messages || []; // [{ id, threadId }]
}

// ── Gmail API: fetch and decode a full message ────────────────────────────────
async function fetchMessage(accessToken, messageId) {
  const url = `https://gmail.googleapis.com/gmail/v1/users/me/messages/${messageId}?format=full`;
  const r = await fetch(url, {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!r.ok) throw new Error(`getMessage: ${await r.text()}`);
  return r.json();
}

function b64urlDecode(str) {
  return Buffer.from(str.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf-8');
}

function extractBodyFromPayload(payload) {
  if (!payload) return '';
  if (payload.body && payload.body.data) return b64urlDecode(payload.body.data);
  if (payload.parts) {
    // prefer text/plain
    const plain = payload.parts.find(p => p.mimeType === 'text/plain');
    if (plain && plain.body && plain.body.data) return b64urlDecode(plain.body.data);
    // fall back to text/html
    const html = payload.parts.find(p => p.mimeType === 'text/html');
    if (html && html.body && html.body.data) return b64urlDecode(html.body.data);
    // recurse into nested multipart
    for (const part of payload.parts) {
      const nested = extractBodyFromPayload(part);
      if (nested) return nested;
    }
  }
  return '';
}

function parseMessage(msg) {
  const headers = (msg.payload && msg.payload.headers) || [];
  const h = name => (headers.find(hdr => hdr.name.toLowerCase() === name.toLowerCase()) || {}).value || '';
  return {
    subject: h('Subject'),
    from:    h('From'),
    body:    extractBodyFromPayload(msg.payload),
    internalDate: Math.floor(Number(msg.internalDate) / 1000), // ms → s
  };
}

// ── Main polling function ─────────────────────────────────────────────────────
/**
 * Called by setInterval every 60s.
 * Loops all mailboxes with gmail_refresh_token, fetches new emails, extracts OTPs.
 */
export async function pollGmailMailboxes() {
  const mailboxes = await dbAll(`
    SELECT * FROM mailboxes WHERE gmail_refresh_token IS NOT NULL
  `);

  if (!mailboxes.length) return;

  for (const mailbox of mailboxes) {
    try {
      const accessToken = await ensureFreshToken(mailbox);
      if (!accessToken) continue;

      // Fetch messages newer than last sync (or last 5 min if never synced)
      const sinceTs = mailbox.gmail_last_sync_ts || 0;
      const msgIds = await listNewMessages(accessToken, sinceTs);

      if (!msgIds.length) {
        // Even if no new messages, update last_sync to now
        const now = Math.floor(Date.now() / 1000);
        await dbRun(`UPDATE mailboxes SET gmail_last_sync_ts = ?, status = 'active' WHERE id = ?`,
          [now, mailbox.id]);
        continue;
      }

      let codesFound = 0;
      const now = Math.floor(Date.now() / 1000);

      for (const msgIdObj of msgIds) {
        const msgId = msgIdObj.id;
        try {
          const msg = await fetchMessage(accessToken, msgId);
          const { subject, from, body, internalDate } = parseMessage(msg);

          // Skip messages older than last sync (shouldn't happen but safety check)
          if (sinceTs && internalDate && internalDate <= sinceTs) continue;

          const code = extractCode(subject, body);
          if (!code) continue;

          // Find slots linked to this mailbox
          const slots = await dbAll('SELECT * FROM slots WHERE mailbox_id = ?', [mailbox.id]);
          for (const slot of slots) {
            const exists = await dbGet(
              'SELECT id FROM codes WHERE slot_id = ? AND code = ? AND received_at > ?',
              [slot.id, code, now - 60]
            );
            if (exists) continue;

            await dbRun(`
              INSERT INTO codes (id, slot_id, code, email_from, email_subj, received_at, expires_at)
              VALUES (?, ?, ?, ?, ?, ?, ?)
            `, [
              randomUUID(),
              slot.id,
              code,
              from.toLowerCase().slice(0, 200),
              subject.slice(0, 200),
              now,
              now + 10 * 60,
            ]);
            codesFound++;
          }
        } catch (msgErr) {
          console.error(`[Gmail] error fetching message ${msgId}:`, msgErr.message);
        }
      }

      await dbRun(`
        UPDATE mailboxes
        SET gmail_last_sync_ts = ?, last_sync = ?, status = 'active', last_error = NULL
        WHERE id = ?
      `, [now, now, mailbox.id]);

      if (codesFound) console.log(`[Gmail] 🔑 ${codesFound} أكواد جديدة ← ${mailbox.email}`);

    } catch (err) {
      console.error(`[Gmail] poll error for ${mailbox.email}:`, err.message);
      await dbRun(`UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?`,
        [err.message.slice(0, 200), mailbox.id]);
    }
  }
}
