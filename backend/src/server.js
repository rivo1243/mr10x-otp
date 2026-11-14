import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import db from './db.js';
import { guessHost, testConnection } from './imap.js';
import { pollAll } from './poller.js';

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;

// ─── Utils ────────────────────────────────────────────────────────────────────
function hashPw(pw) {
  return createHash('sha256').update(pw + (process.env.SECRET || 'mr10x')).digest('hex');
}
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const seller = db.prepare('SELECT * FROM sellers WHERE id = ?').get(token);
  if (!seller) return res.status(401).json({ error: 'Invalid token' });
  req.seller = seller;
  next();
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
app.post('/api/register', (req, res) => {
  const { name, email, password } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const existing = db.prepare('SELECT id FROM sellers WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Email already registered' });
  const id = randomUUID();
  db.prepare('INSERT INTO sellers (id, name, email, password) VALUES (?, ?, ?, ?)')
    .run(id, name, email.toLowerCase(), hashPw(password));
  res.json({ token: id, name });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const seller = db.prepare('SELECT * FROM sellers WHERE email = ?').get(String(email).toLowerCase());
  if (!seller || seller.password !== hashPw(password))
    return res.status(401).json({ error: 'Invalid credentials' });
  res.json({ token: seller.id, name: seller.name });
});

// ─── Mailboxes ─────────────────────────────────────────────────────────────────
app.get('/api/mailboxes', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT id, email, imap_host, imap_port, label, status, last_sync, last_error FROM mailboxes WHERE seller_id = ?')
    .all(req.seller.id);
  res.json(rows);
});

app.post('/api/mailboxes', authMiddleware, async (req, res) => {
  const { email, password, host, port, label } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  const imapHost = host || guessHost(email);
  const imapPort = Number(port) || 993;
  try {
    await testConnection(email, password, imapHost, imapPort);
  } catch (e) {
    return res.status(400).json({ error: `Connection failed: ${e.message}` });
  }
  const id = randomUUID();
  db.prepare(`INSERT INTO mailboxes (id, seller_id, email, imap_host, imap_port, password, label)
    VALUES (?, ?, ?, ?, ?, ?, ?)`)
    .run(id, req.seller.id, email.toLowerCase(), imapHost, imapPort, password, label || '');
  res.json({ id, email, imap_host: imapHost, status: 'connected' });
});

app.delete('/api/mailboxes/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM mailboxes WHERE id = ? AND seller_id = ?').run(req.params.id, req.seller.id);
  res.json({ ok: true });
});

// ─── Slots ────────────────────────────────────────────────────────────────────
app.get('/api/slots', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT s.id, s.label, s.token, s.mailbox_id, s.created_at,
           m.email as mailbox_email,
           (SELECT code FROM codes WHERE slot_id = s.id ORDER BY received_at DESC LIMIT 1) as latest_code
    FROM slots s JOIN mailboxes m ON m.id = s.mailbox_id
    WHERE s.seller_id = ? ORDER BY s.created_at DESC`)
    .all(req.seller.id);
  res.json(rows);
});

app.post('/api/slots', authMiddleware, (req, res) => {
  const { mailbox_id, label, count = 1 } = req.body || {};
  if (!mailbox_id || !label) return res.status(400).json({ error: 'mailbox_id and label required' });
  const mailbox = db.prepare('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?').get(mailbox_id, req.seller.id);
  if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

  const created = [];
  const n = Math.min(Number(count) || 1, 100);
  for (let i = 0; i < n; i++) {
    const id = randomUUID();
    const token = randomUUID().replace(/-/g, '');
    db.prepare('INSERT INTO slots (id, seller_id, mailbox_id, label, token) VALUES (?, ?, ?, ?, ?)')
      .run(id, req.seller.id, mailbox_id, label, token);
    created.push({ id, token, label });
  }
  res.json(created);
});

app.delete('/api/slots/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM slots WHERE id = ? AND seller_id = ?').run(req.params.id, req.seller.id);
  res.json({ ok: true });
});

// ─── Customer endpoint (public) ───────────────────────────────────────────────
app.get('/api/code/:token', (req, res) => {
  const slot = db.prepare('SELECT * FROM slots WHERE token = ?').get(req.params.token);
  if (!slot) return res.status(404).json({ error: 'Invalid link' });

  const code = db.prepare(`
    SELECT code, received_at, expires_at FROM codes
    WHERE slot_id = ? AND expires_at > ?
    ORDER BY received_at DESC LIMIT 1`)
    .get(slot.id, Math.floor(Date.now() / 1000));

  if (!code) return res.json({ status: 'waiting', label: slot.label });

  // وضع علامة أنه شُوهد
  db.prepare('UPDATE codes SET viewed = 1 WHERE slot_id = ? AND code = ?').run(slot.id, code.code);

  res.json({
    status: 'ready',
    code: code.code,
    label: slot.label,
    expires_in: code.expires_at - Math.floor(Date.now() / 1000)
  });
});

// ─── Polling ──────────────────────────────────────────────────────────────────
setInterval(() => pollAll(), 15_000); // كل 15 ثانية
pollAll(); // تشغيل فوري عند البدء

app.listen(PORT, () => {
  console.log(`Mr10x OTP Backend running on port ${PORT}`);
});
