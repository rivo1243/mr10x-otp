import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID, randomInt, randomBytes, createHash, pbkdf2Sync, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import { dbGet, dbAll, dbRun } from './db.js';
import { pollAll } from './poller.js';
import { encryptPassword, decryptPassword } from './crypto-utils.js';
import { extractCode } from './extract.js';
import {
  gmailEnabled, makeOAuthState, parseOAuthState,
  getAuthUrl, exchangeCode, getGmailAddress,
  pollGmailMailboxes
} from './gmail.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

// ─── CORS ─────────────────────────────────────────────────────────────────────
const CORS_ORIGIN = process.env.CORS_ORIGIN;
const app = express();
// N-02: trust the first hop proxy so req.ip gives the real client IP
app.set('trust proxy', 1);
if (CORS_ORIGIN) {
  app.use(cors({ origin: CORS_ORIGIN }));
}
// F-02: cap request body at 64 KB to prevent DoS via large payloads
app.use(express.json({ limit: '64kb' }));
app.use('/api/inbound', express.text({ limit: '64kb' }));
app.use('/api/inbound', express.urlencoded({ extended: false, limit: '64kb' }));
// F-03: security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'");
  next();
});

// ─── Serve Frontend ───────────────────────────────────────────────────────────
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, '../../frontend/landing.html'));
});

app.get('/admin', (req, res) => {
  res.sendFile(join(__dirname, '../../frontend/admin.html'));
});

app.post('/go-admin', (req, res) => {
  const { email, pass } = req.body || {};
  const ADMIN_EMAIL_ENV = process.env.ADMIN_EMAIL || '';
  if (!safeCompare(pass || '', ADMIN_PASS)) return res.status(401).json({ error: 'Unauthorized' });
  if (ADMIN_EMAIL_ENV && (!email || email.toLowerCase() !== ADMIN_EMAIL_ENV.toLowerCase()))
    return res.status(401).json({ error: 'Unauthorized' });
  const sessionToken = createAdminSession();
  res.json({ token: sessionToken });
});

app.use(express.static(join(__dirname, '../../frontend')));

const PORT = process.env.PORT || 4000;

// ─── Utils ────────────────────────────────────────────────────────────────────
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEYLEN = 32;

function hashPw(pw, salt) {
  if (salt) {
    const pepper = process.env.SECRET || 'mr10x';
    return pbkdf2Sync(pw + pepper, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, 'sha256').toString('hex');
  }
  return createHash('sha256').update(pw + (process.env.SECRET || 'mr10x')).digest('hex');
}

function hashPwLegacy(pw, salt) {
  return createHash('sha256')
    .update(salt + pw + (process.env.SECRET || 'mr10x'))
    .digest('hex');
}

function generateSalt() {
  return randomBytes(16).toString('hex');
}

function safeCompare(a, b) {
  try {
    const ba = Buffer.from(String(a));
    const bb = Buffer.from(String(b));
    if (ba.length !== bb.length) {
      timingSafeEqual(ba, ba);
      return false;
    }
    return timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

// ─── Rate limiting ────────────────────────────────────────────────────────────
const rateLimitStore = new Map();

function rateLimit(key, maxPerWindow = 10, windowMs = 60_000) {
  const now = Date.now();
  let entry = rateLimitStore.get(key);
  if (!entry || entry.resetAt < now) {
    entry = { count: 0, resetAt: now + windowMs };
    rateLimitStore.set(key, entry);
  }
  entry.count++;
  return entry.count <= maxPerWindow;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitStore) {
    if (v.resetAt < now) rateLimitStore.delete(k);
  }
}, 5 * 60_000);

// ─── Auth middleware ───────────────────────────────────────────────────────────
async function authMiddleware(req, res, next) {
  try {
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Unauthorized' });
    const seller = await dbGet('SELECT * FROM sellers WHERE api_token = ?', [token]);
    if (!seller) return res.status(401).json({ error: 'Invalid token' });
    if (seller.status === 'pending')  return res.status(403).json({ error: 'pending' });
    if (seller.status === 'rejected') return res.status(403).json({ error: 'rejected' });
    if (seller.subscription_expires_at && parseInt(seller.subscription_expires_at) < Math.floor(Date.now() / 1000)) {
      return res.status(403).json({ error: 'subscription_expired', message: 'انتهت صلاحية اشتراكك. تواصل مع الدعم للتجديد.' });
    }
    req.seller = seller;
    next();
  } catch (err) {
    console.error('[authMiddleware]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
}

// ─── Admin Auth ───────────────────────────────────────────────────────────────
const ADMIN_PASS = process.env.ADMIN_PASS;
if (!ADMIN_PASS) {
  console.error('[FATAL] ADMIN_PASS environment variable is not set. Set it before starting the server.');
  process.exit(1);
}

const adminSessions = new Map();

function createAdminSession() {
  const token = randomBytes(32).toString('hex');
  adminSessions.set(token, { expiresAt: Date.now() + 8 * 60 * 60_000 });
  return token;
}

function validateAdminSession(token) {
  const s = adminSessions.get(token);
  if (!s) return false;
  if (s.expiresAt < Date.now()) {
    adminSessions.delete(token);
    return false;
  }
  return true;
}

setInterval(() => {
  const now = Date.now();
  for (const [k, v] of adminSessions) {
    if (v.expiresAt < now) adminSessions.delete(k);
  }
}, 60 * 60_000);

function adminMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const sessionToken = authHeader.startsWith('AdminSession ')
    ? authHeader.slice('AdminSession '.length)
    : null;
  if (sessionToken && validateAdminSession(sessionToken)) return next();
  return res.status(401).json({ error: 'Unauthorized' });
}

// POST /api/admin/login
app.post('/api/admin/login', (req, res) => {
  const ip = req.ip;
  if (!rateLimit(`admin-login:${ip}`, 5, 15 * 60_000)) {
    return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  }
  const { password } = req.body || {};
  if (!safeCompare(password || '', ADMIN_PASS))
    return res.status(401).json({ error: 'Invalid password' });
  const token = createAdminSession();
  res.json({ token, expiresIn: 8 * 3600 });
});

// ─── HTML escaping ────────────────────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ─── Mailer (Mailjet API) ─────────────────────────────────────────────────────
const MAILJET_API_KEY    = process.env.MAILJET_API_KEY;
const MAILJET_SECRET_KEY = process.env.MAILJET_SECRET_KEY;
const MAILJET_FROM_EMAIL = process.env.MAILJET_FROM_EMAIL || 'noreply@mr10x.app';
const MAILJET_FROM_NAME  = 'Mr10x';

async function sendEmail({ to, subject, html }) {
  if (!MAILJET_API_KEY || !MAILJET_SECRET_KEY) {
    console.error(`[MAIL ERROR] Mailjet keys not set — cannot send email`);
    throw new Error('Mailjet API keys not configured');
  }

  const auth = Buffer.from(`${MAILJET_API_KEY}:${MAILJET_SECRET_KEY}`).toString('base64');

  const res = await fetch('https://api.mailjet.com/v3.1/send', {
    method: 'POST',
    headers: {
      'Authorization': `Basic ${auth}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      Messages: [
        {
          From: { Email: MAILJET_FROM_EMAIL, Name: MAILJET_FROM_NAME },
          To:   [{ Email: to }],
          Subject: subject,
          HTMLPart: html
        }
      ]
    })
  });

  if (!res.ok) {
    const err = await res.text();
    throw new Error(`Mailjet error ${res.status}: ${err}`);
  }

  const data = await res.json();
  const status = data?.Messages?.[0]?.Status;
  if (status && status !== 'success') {
    throw new Error(`Mailjet delivery failed: ${status}`);
  }
}

async function sendVerificationEmail(toEmail, toName, code) {
  const safeName = escapeHtml(toName);
  const safeCode = escapeHtml(code);
  await sendEmail({
    to: toEmail,
    subject: 'كود تأكيد التسجيل في Mr10x',
    html: `
      <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 480px; margin: auto;">
        <h2 style="color: #7c3aed;">مرحباً ${safeName} 👋</h2>
        <p>شكراً لتسجيلك في <strong>Mr10x</strong>. أدخل الكود التالي لتأكيد بريدك الإلكتروني:</p>
        <div style="background: #1a1a2e; border: 2px solid #7c3aed; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0;">
          <span style="font-size: 36px; font-weight: bold; color: #a855f7; letter-spacing: 8px;">${safeCode}</span>
        </div>
        <p style="color: #888;">ينتهي الكود خلال 15 دقيقة.</p>
        <p style="color: #888; font-size: 12px;">إذا لم تطلب هذا الكود تجاهل هذه الرسالة.</p>
      </div>
    `
  });
}

// ─── Auth ─────────────────────────────────────────────────────────────────────
// POST /api/register
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password, phone, plan_type } = req.body || {};
    if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
    if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

    const existing = await dbGet('SELECT id FROM sellers WHERE email = ?', [email.toLowerCase()]);
    if (existing) return res.status(409).json({ error: 'Email already registered' });

    const validPlan = ['plan1', 'plan2', 'plan3'].includes(plan_type) ? plan_type : 'plan2';
    const code = String(randomInt(100000, 1000000));
    const expiresAt = Math.floor(Date.now() / 1000) + 900;
    const verifyId = randomUUID();

    await dbRun('DELETE FROM email_verifications WHERE email = ?', [email.toLowerCase()]);

    const salt = generateSalt();
    await dbRun(
      'INSERT INTO email_verifications (id, email, code, name, password, phone, plan_type, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
      [verifyId, email.toLowerCase(), code, name, hashPw(password, salt) + ':' + salt, phone || '', validPlan, expiresAt]
    );

    try {
      await sendVerificationEmail(email, name, code);
    } catch (e) {
      console.error('[MAIL ERROR]', e.message);
    }

    res.json({ verify: true, verifyId });
  } catch (err) {
    console.error('[/api/register]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/verify-email
app.post('/api/verify-email', async (req, res) => {
  try {
    const { verifyId, code } = req.body || {};
    if (!verifyId || !code) return res.status(400).json({ error: 'Missing fields' });

    const ip = req.ip;
    if (!rateLimit(`verify-email:${ip}`, 10, 15 * 60_000)) {
      return res.status(429).json({ error: 'Too many attempts. Try again later.' });
    }

    const record = await dbGet('SELECT * FROM email_verifications WHERE id = ?', [verifyId]);
    if (!record) return res.status(404).json({ error: 'انتهت صلاحية الكود أو غير صحيح' });
    if (record.used) return res.status(400).json({ error: 'تم استخدام هذا الكود مسبقاً' });
    if (parseInt(record.expires_at) < Math.floor(Date.now() / 1000)) {
      await dbRun('DELETE FROM email_verifications WHERE id = ?', [verifyId]);
      return res.status(400).json({ error: 'انتهت صلاحية الكود، أعد التسجيل' });
    }
    if (!safeCompare(String(code).trim(), record.code)) {
      return res.status(400).json({ error: 'الكود غير صحيح' });
    }

    const existing = await dbGet('SELECT id FROM sellers WHERE email = ?', [record.email]);
    if (existing) return res.status(409).json({ error: 'البريد الإلكتروني مسجل مسبقاً' });

    let storedHash = record.password;
    let storedSalt = null;
    const colonIdx = record.password.lastIndexOf(':');
    if (colonIdx > 0 && colonIdx < record.password.length - 1) {
      const potentialSalt = record.password.slice(colonIdx + 1);
      if (potentialSalt.length === 32) {
        storedHash = record.password.slice(0, colonIdx);
        storedSalt = potentialSalt;
      }
    }

    const sellerId = randomUUID();
    const apiToken = randomUUID();
    const sellerPlan = ['plan1', 'plan2', 'plan3'].includes(record.plan_type) ? record.plan_type : 'plan2';

    await dbRun(
      'INSERT INTO sellers (id, name, email, password, salt, phone, status, plan_type, api_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [sellerId, record.name, record.email, storedHash, storedSalt, record.phone, 'pending', sellerPlan, apiToken]
    );
    await dbRun('UPDATE email_verifications SET used = 1 WHERE id = ?', [verifyId]);

    res.json({ pending: true });
  } catch (err) {
    console.error('[/api/verify-email]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/login
app.post('/api/login', async (req, res) => {
  try {
    const ip = req.ip;
    if (!rateLimit(`login:${ip}`, 10, 15 * 60_000)) {
      return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
    }

    const { email, password } = req.body || {};
    const seller = await dbGet('SELECT * FROM sellers WHERE email = ?', [String(email).toLowerCase()]);
    if (!seller) return res.status(401).json({ error: 'Invalid credentials' });

    let expectedHash = hashPw(password, seller.salt || null);
    let needsMigration = false;

    if (!safeCompare(expectedHash, seller.password)) {
      if (seller.salt) {
        const legacyHash = hashPwLegacy(password, seller.salt);
        if (!safeCompare(legacyHash, seller.password)) {
          return res.status(401).json({ error: 'Invalid credentials' });
        }
        needsMigration = true;
      } else {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
    }

    if (seller.status === 'pending')
      return res.status(403).json({ error: 'pending', message: 'حسابك قيد المراجعة، سنتواصل معك على الواتساب قريباً.' });

    if (!seller.salt || needsMigration) {
      const newSalt = generateSalt();
      const newHash = hashPw(password, newSalt);
      await dbRun('UPDATE sellers SET password = ?, salt = ? WHERE id = ?', [newHash, newSalt, seller.id]);
    }

    res.json({
      token: seller.api_token,
      name: seller.name,
      subscription_expires_at: seller.subscription_expires_at || null,
      plan_type: seller.plan_type || 'plan2'
    });
  } catch (err) {
    console.error('[/api/login]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/forgot-password
app.post('/api/forgot-password', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'Email required' });

    const ip = req.ip;
    if (!rateLimit(`fp:${ip}`, 5, 10 * 60_000)) {
      return res.status(429).json({ error: 'Too many requests. Please wait before trying again.' });
    }

    const seller = await dbGet('SELECT * FROM sellers WHERE email = ?', [String(email).toLowerCase()]);
    if (!seller) return res.json({ ok: true });

    const rawToken = randomBytes(32).toString('hex');
    const tokenHash = createHash('sha256').update(rawToken).digest('hex');
    const expiresAt = Math.floor(Date.now() / 1000) + 60 * 30;

    await dbRun(
      'INSERT INTO password_resets (id, email, token, expires_at) VALUES (?, ?, ?, ?)',
      [randomUUID(), seller.email, tokenHash, expiresAt]
    );

    const BASE_URL = process.env.BASE_URL;
    if (!BASE_URL) {
      console.error('[forgot-password] BASE_URL env var not set');
      return res.json({ ok: true });
    }
    const resetLink = `${BASE_URL}/reset-password.html?token=${rawToken}`;

    try {
      const safeSellerName = escapeHtml(seller.name);
      await sendEmail({
        to: seller.email,
        subject: 'إعادة تعيين كلمة المرور — Mr10x',
        html: `
          <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; background:#0f0f1a; color:#e2e8f0; padding:32px; border-radius:12px;">
            <h2 style="color:#a855f7; margin-bottom:8px;">Mr10x</h2>
            <p>مرحباً ${safeSellerName}،</p>
            <p>طلبت إعادة تعيين كلمة مرورك. اضغط الزر أدناه:</p>
            <a href="${resetLink}" style="display:inline-block;margin:20px 0;padding:14px 28px;background:#7c3aed;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;">إعادة تعيين كلمة المرور</a>
            <p style="color:#94a3b8;font-size:13px;">الرابط صالح لمدة 30 دقيقة فقط. إذا لم تطلب هذا، تجاهل الرسالة.</p>
          </div>
        `
      });
    } catch (mailErr) {
      console.error(`[forgot-password] mail error:`, mailErr.message);
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('[/api/forgot-password]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/reset-password
app.post('/api/reset-password', async (req, res) => {
  try {
    const { token, password } = req.body || {};
    if (!token || !password) return res.status(400).json({ error: 'Missing fields' });
    if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

    const tokenHash = createHash('sha256').update(token).digest('hex');
    const record = await dbGet(
      'SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > ?',
      [tokenHash, Math.floor(Date.now() / 1000)]
    );

    if (!record) return res.status(400).json({ error: 'الرابط غير صالح أو منتهي الصلاحية' });

    const newSalt = generateSalt();
    const newHash = hashPw(password, newSalt);
    await dbRun('UPDATE sellers SET password = ?, salt = ? WHERE email = ?', [newHash, newSalt, record.email]);
    await dbRun('UPDATE password_resets SET used = 1 WHERE token = ?', [tokenHash]);

    res.json({ ok: true });
  } catch (err) {
    console.error('[/api/reset-password]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/me
app.get('/api/me', authMiddleware, async (req, res) => {
  try {
    const seller = await dbGet(
      'SELECT id, name, email, phone, status, subscription_expires_at, plan_type FROM sellers WHERE id = ?',
      [req.seller.id]
    );
    const now = Math.floor(Date.now() / 1000);
    let subscription_days_left;
    if (!seller.subscription_expires_at) {
      subscription_days_left = null;
    } else if (parseInt(seller.subscription_expires_at) > now) {
      subscription_days_left = Math.ceil((parseInt(seller.subscription_expires_at) - now) / 86400);
    } else {
      subscription_days_left = 0;
    }
    res.json({ ...seller, subscription_days_left, plan: seller.plan_type });
  } catch (err) {
    console.error('[/api/me]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Admin API ────────────────────────────────────────────────────────────────
app.get('/api/admin/sellers', adminMiddleware, async (req, res) => {
  try {
    const sellers = await dbAll(
      'SELECT id, name, email, phone, status, created_at, subscription_expires_at, plan_type FROM sellers ORDER BY created_at DESC'
    );
    res.json(sellers);
  } catch (err) {
    console.error('[/api/admin/sellers]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/admin/sellers/:id/approve', adminMiddleware, async (req, res) => {
  try {
    await dbRun('UPDATE sellers SET status = ? WHERE id = ?', ['active', req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[approve]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/admin/sellers/:id/reject', adminMiddleware, async (req, res) => {
  try {
    await dbRun('UPDATE sellers SET status = ? WHERE id = ?', ['rejected', req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[reject]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/admin/sellers/:id', adminMiddleware, async (req, res) => {
  try {
    await dbRun('DELETE FROM sellers WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[delete seller]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/admin/sellers/:id/subscription', adminMiddleware, async (req, res) => {
  try {
    const { expires_at } = req.body || {};
    const ts = expires_at ? Math.floor(new Date(expires_at).getTime() / 1000) : null;
    await dbRun('UPDATE sellers SET subscription_expires_at = ? WHERE id = ?', [ts, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[subscription]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/admin/sellers/:id/plan', adminMiddleware, async (req, res) => {
  try {
    const { plan_type } = req.body || {};
    if (!['plan1', 'plan2', 'plan3'].includes(plan_type))
      return res.status(400).json({ error: 'plan_type يجب أن يكون plan1 أو plan2 أو plan3' });
    await dbRun('UPDATE sellers SET plan_type = ? WHERE id = ?', [plan_type, req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[plan]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
  try {
    const now = Math.floor(Date.now() / 1000);
    const [r1, r2, r3, r4, r5, r6, r7, r8] = await Promise.all([
      dbGet("SELECT COUNT(*) as n FROM sellers"),
      dbGet("SELECT COUNT(*) as n FROM sellers WHERE status = 'active'"),
      dbGet("SELECT COUNT(*) as n FROM sellers WHERE status = 'pending'"),
      dbGet("SELECT COUNT(*) as n FROM mailboxes"),
      dbGet("SELECT COUNT(*) as n FROM slots"),
      dbGet("SELECT COUNT(*) as n FROM codes"),
      dbGet("SELECT COUNT(*) as n FROM codes WHERE viewed = 1"),
      dbGet("SELECT COUNT(*) as n FROM sellers WHERE subscription_expires_at IS NOT NULL AND subscription_expires_at > ?", [now])
    ]);
    res.json({
      totalSellers:   parseInt(r1.n),
      activeSellers:  parseInt(r2.n),
      pendingSellers: parseInt(r3.n),
      totalMailboxes: parseInt(r4.n),
      totalSlots:     parseInt(r5.n),
      totalCodes:     parseInt(r6.n),
      codesViewed:    parseInt(r7.n),
      activeSubs:     parseInt(r8.n)
    });
  } catch (err) {
    console.error('[/api/admin/stats]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Gmail OAuth Routes ────────────────────────────────────────────────────────

app.get('/api/auth/gmail/start', authMiddleware, async (req, res) => {
  try {
    if (!gmailEnabled()) return res.status(503).json({ error: 'Gmail OAuth not configured' });
    const { mailbox_id } = req.query;
    if (!mailbox_id) return res.status(400).json({ error: 'mailbox_id required' });

    const mailbox = await dbGet('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?', [mailbox_id, req.seller.id]);
    if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

    const state = makeOAuthState(mailbox_id, req.seller.id);
    res.json({ url: getAuthUrl(state) });
  } catch (err) {
    console.error('[gmail/start]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/gmail/callback', async (req, res) => {
  try {
    if (!gmailEnabled()) return res.status(503).send('Gmail OAuth not configured');
    const { code, state, error } = req.query;

    if (error) return res.redirect(`/index.html?gmail_error=${encodeURIComponent(error)}`);
    if (!code || !state) return res.redirect('/index.html?gmail_error=missing_params');

    const parsed = parseOAuthState(state);
    if (!parsed) return res.redirect('/index.html?gmail_error=invalid_state');

    const { mailboxId, sellerId } = parsed;

    const mailbox = await dbGet('SELECT id, email FROM mailboxes WHERE id = ? AND seller_id = ?', [mailboxId, sellerId]);
    if (!mailbox) return res.redirect('/?gmail_error=mailbox_not_found');

    const tokens = await exchangeCode(code);
    const now = Math.floor(Date.now() / 1000);
    const expiry = now + (tokens.expires_in || 3600);

    let gmailEmail = null;
    try { gmailEmail = await getGmailAddress(tokens.access_token); } catch {}

    await dbRun(
      `UPDATE mailboxes
       SET gmail_refresh_token = ?, gmail_access_token = ?, gmail_token_expiry = ?,
           gmail_email = ?, gmail_last_sync_ts = ?, status = 'active', last_error = NULL
       WHERE id = ?`,
      [tokens.refresh_token, tokens.access_token, expiry, gmailEmail || mailbox.email, now, mailboxId]
    );

    res.redirect('/index.html?gmail_connected=1');
  } catch (err) {
    console.error('[Gmail OAuth] callback error:', err.message);
    res.redirect(`/index.html?gmail_error=${encodeURIComponent('فشل الاتصال بـ Gmail')}`);
  }
});

app.post('/api/mailboxes/:id/gmail-disconnect', authMiddleware, async (req, res) => {
  try {
    const mailbox = await dbGet('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?', [req.params.id, req.seller.id]);
    if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

    await dbRun(
      `UPDATE mailboxes
       SET gmail_refresh_token = NULL, gmail_access_token = NULL,
           gmail_token_expiry = NULL, gmail_email = NULL, gmail_last_sync_ts = NULL,
           status = 'active'
       WHERE id = ?`,
      [req.params.id]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('[gmail-disconnect]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Mailboxes ─────────────────────────────────────────────────────────────────

app.get('/api/mailboxes', authMiddleware, async (req, res) => {
  try {
    const rows = await dbAll(
      `SELECT id, email, label, status, last_sync, last_error, webhook_token,
              gmail_email,
              CASE WHEN gmail_refresh_token IS NOT NULL THEN 1 ELSE 0 END as gmail_connected
       FROM mailboxes WHERE seller_id = ?`,
      [req.seller.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('[/api/mailboxes GET]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/mailboxes', authMiddleware, async (req, res) => {
  try {
    const { email, label } = req.body || {};
    if (!email) return res.status(400).json({ error: 'البريد الإلكتروني مطلوب' });

    const mailboxCount = await dbGet('SELECT COUNT(*) as cnt FROM mailboxes WHERE seller_id = ?', [req.seller.id]);
    if (parseInt(mailboxCount.cnt) >= 500)
      return res.status(400).json({ error: 'تعذّر إضافة صندوق البريد، يرجى التواصل مع الدعم.' });

    const id = randomUUID();
    const webhookToken = randomUUID();
    await dbRun(
      `INSERT INTO mailboxes (id, seller_id, email, imap_host, imap_port, password, label, status, webhook_token)
       VALUES (?, ?, ?, '', 993, '', ?, 'active', ?)`,
      [id, req.seller.id, email.toLowerCase().trim(), label || '', webhookToken]
    );
    res.json({ id, email, label: label || '', status: 'active', webhook_token: webhookToken });
  } catch (err) {
    console.error('[/api/mailboxes POST]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/mailboxes/:id', authMiddleware, async (req, res) => {
  try {
    await dbRun('DELETE FROM mailboxes WHERE id = ? AND seller_id = ?', [req.params.id, req.seller.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[mailboxes DELETE]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Inbound Webhook ───────────────────────────────────────────────────────────
app.post('/api/inbound/:token', async (req, res) => {
  try {
    const mailbox = await dbGet('SELECT * FROM mailboxes WHERE webhook_token = ?', [req.params.token]);
    if (!mailbox) return res.status(404).json({ error: 'Invalid token' });

    let subject = '';
    let body = '';
    const ct = (req.headers['content-type'] || '').toLowerCase();

    if (ct.includes('application/json')) {
      const p = req.body || {};
      subject = String(p.subject || p.Subject || '');
      body = String(p.text || p.plain || p.body || p.html || '');
    } else {
      body = String(req.body?.text || req.body?.body || '');
      subject = String(req.body?.subject || '');
    }

    if (!body && typeof req.body === 'string') body = req.body;

    const code = extractCode(subject, body);
    if (!code) {
      console.log(`[Webhook] لا كود في إيميل لصندوق ${mailbox.email}`);
      return res.json({ ok: true, extracted: false });
    }

    const slots = await dbAll('SELECT * FROM slots WHERE mailbox_id = ?', [mailbox.id]);
    const receivedTs = Math.floor(Date.now() / 1000);

    for (const slot of slots) {
      const exists = await dbGet(
        'SELECT id FROM codes WHERE slot_id = ? AND code = ? AND received_at > ?',
        [slot.id, code, receivedTs - 60]
      );
      if (exists) continue;

      await dbRun(
        `INSERT INTO codes (id, slot_id, code, email_from, email_subj, received_at, expires_at)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
        [
          randomUUID(), slot.id, code,
          String(req.body?.from || req.body?.sender || '').toLowerCase().slice(0, 200),
          subject.slice(0, 200),
          receivedTs,
          receivedTs + 10 * 60
        ]
      );
      console.log(`[Webhook] 🔑 كود جديد ${code} → slot ${slot.id}`);
    }

    await dbRun("UPDATE mailboxes SET last_sync = ?, status = 'active', last_error = NULL WHERE id = ?", [receivedTs, mailbox.id]);
    res.json({ ok: true, extracted: true, code });
  } catch (err) {
    console.error('[/api/inbound]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Slots ────────────────────────────────────────────────────────────────────
app.get('/api/slots', authMiddleware, async (req, res) => {
  try {
    const rows = await dbAll(
      `SELECT s.id, s.label, s.token, s.mailbox_id, s.created_at,
              s.account_email,
              m.email as mailbox_email,
              (SELECT code FROM codes WHERE slot_id = s.id ORDER BY received_at DESC LIMIT 1) as latest_code
       FROM slots s JOIN mailboxes m ON m.id = s.mailbox_id
       WHERE s.seller_id = ? ORDER BY s.created_at DESC`,
      [req.seller.id]
    );
    res.json(rows);
  } catch (err) {
    console.error('[/api/slots GET]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/slots', authMiddleware, async (req, res) => {
  try {
    const { mailbox_id, label, count = 1, account_email = '', account_password = '' } = req.body || {};
    if (!mailbox_id || !label) return res.status(400).json({ error: 'mailbox_id and label required' });

    const mailbox = await dbGet('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?', [mailbox_id, req.seller.id]);
    if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

    const seller = await dbGet('SELECT plan_type FROM sellers WHERE id = ?', [req.seller.id]);
    const planType = seller?.plan_type || 'plan2';
    if (planType === 'plan1') {
      const existingCount = await dbGet('SELECT COUNT(*) as n FROM slots WHERE seller_id = ?', [req.seller.id]);
      if (parseInt(existingCount.n) >= 1)
        return res.status(403).json({ error: 'plan_limit', message: 'باقتك تسمح بتطبيق واحد فقط. يرجى الترقية للباقة الثانية أو الثالثة.' });
    }

    const created = [];
    const n = Math.min(Number(count) || 1, 10);
    const encryptedAccountPassword = account_password ? encryptPassword(account_password) : '';
    for (let i = 0; i < n; i++) {
      const id = randomUUID();
      const token = randomBytes(16).toString('hex');
      await dbRun(
        'INSERT INTO slots (id, seller_id, mailbox_id, label, token, account_email, account_password, account_password_encrypted) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [id, req.seller.id, mailbox_id, label, token, account_email, encryptedAccountPassword, encryptedAccountPassword ? 1 : 0]
      );
      created.push({ id, token, label, account_email });
    }
    res.json(created);
  } catch (err) {
    console.error('[/api/slots POST]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/slots/:id', authMiddleware, async (req, res) => {
  try {
    const { account_email, account_password, label } = req.body || {};
    const slot = await dbGet('SELECT id FROM slots WHERE id = ? AND seller_id = ?', [req.params.id, req.seller.id]);
    if (!slot) return res.status(404).json({ error: 'Slot not found' });

    if (account_email !== undefined)
      await dbRun('UPDATE slots SET account_email = ? WHERE id = ?', [account_email, req.params.id]);
    if (account_password !== undefined) {
      const enc = account_password ? encryptPassword(account_password) : '';
      await dbRun('UPDATE slots SET account_password = ?, account_password_encrypted = ? WHERE id = ?', [enc, enc ? 1 : 0, req.params.id]);
    }
    if (label !== undefined)
      await dbRun('UPDATE slots SET label = ? WHERE id = ?', [label, req.params.id]);

    res.json({ ok: true });
  } catch (err) {
    console.error('[/api/slots PATCH]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.patch('/api/slots/:id/reset', authMiddleware, async (req, res) => {
  try {
    const slot = await dbGet('SELECT id FROM slots WHERE id = ? AND seller_id = ?', [req.params.id, req.seller.id]);
    if (!slot) return res.status(404).json({ error: 'Slot not found' });
    await dbRun('UPDATE slots SET code_attempts = 0 WHERE id = ?', [req.params.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[slots reset]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

app.delete('/api/slots/:id', authMiddleware, async (req, res) => {
  try {
    await dbRun('DELETE FROM slots WHERE id = ? AND seller_id = ?', [req.params.id, req.seller.id]);
    res.json({ ok: true });
  } catch (err) {
    console.error('[slots DELETE]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Customer endpoint (public) ───────────────────────────────────────────────
app.get('/api/slot/:token', async (req, res) => {
  try {
    const ip = req.ip;
    if (!rateLimit(`slot:${ip}`, 10, 60_000)) {
      return res.status(429).json({ error: 'Too many requests.' });
    }
    const slot = await dbGet('SELECT * FROM slots WHERE token = ?', [req.params.token]);
    if (!slot) return res.status(404).json({ error: 'Invalid link' });
    res.json({
      label: slot.label,
      account_email: slot.account_email || '',
      attempts_left: Math.max(0, 2 - (slot.code_attempts || 0))
    });
  } catch (err) {
    console.error('[/api/slot]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/code/:token
app.get('/api/code/:token', async (req, res) => {
  try {
    const ip = req.ip;
    if (!rateLimit(`code:${ip}`, 20, 60_000)) {
      return res.status(429).json({ error: 'Too many requests.' });
    }

    const slot = await dbGet('SELECT * FROM slots WHERE token = ?', [req.params.token]);
    if (!slot) return res.status(404).json({ error: 'Invalid link' });

    const attempts = slot.code_attempts || 0;
    if (attempts >= 2) {
      return res.json({
        status: 'exhausted',
        label: slot.label,
        account_email: slot.account_email || ''
      });
    }

    const code = await dbGet(
      `SELECT code, received_at, expires_at FROM codes
       WHERE slot_id = ? AND expires_at > ?
       ORDER BY received_at DESC LIMIT 1`,
      [slot.id, Math.floor(Date.now() / 1000)]
    );

    if (!code) return res.json({ status: 'waiting', label: slot.label });

    await dbRun('UPDATE slots SET code_attempts = code_attempts + 1 WHERE id = ?', [slot.id]);
    await dbRun('UPDATE codes SET viewed = 1 WHERE slot_id = ? AND code = ?', [slot.id, code.code]);

    res.json({
      status: 'ready',
      code: code.code,
      label: slot.label,
      expires_in: parseInt(code.expires_at) - Math.floor(Date.now() / 1000),
      attempts_left: Math.max(0, 2 - (attempts + 1)),
      account_email: slot.account_email || ''
    });
  } catch (err) {
    console.error('[/api/code]', err.message);
    res.status(500).json({ error: 'Server error' });
  }
});

// ─── Polling ──────────────────────────────────────────────────────────────────
pollAll();

if (gmailEnabled()) {
  setTimeout(() => pollGmailMailboxes(), 10_000);
  setInterval(() => pollGmailMailboxes(), 60_000);
  console.log('[Gmail] Polling enabled — every 60s');
} else {
  console.log('[Gmail] OAuth not configured (GOOGLE_CLIENT_ID/SECRET/REDIRECT_URI missing)');
}

app.listen(PORT, () => {
  console.log(`Mr10x OTP Backend running on port ${PORT}`);
});
