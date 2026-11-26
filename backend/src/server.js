import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID, randomInt, randomBytes, createHash, pbkdf2Sync, timingSafeEqual } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import db from './db.js';
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
// (prevents X-Forwarded-For spoofing on Railway / reverse proxies)
app.set('trust proxy', 1);
// F-08: only enable CORS when CORS_ORIGIN is explicitly set.
// Calling cors(false) or cors() defaults to origin:'*' — omit entirely when not needed.
if (CORS_ORIGIN) {
  app.use(cors({ origin: CORS_ORIGIN }));
}
// F-02: cap request body at 64 KB to prevent DoS via large payloads
app.use(express.json({ limit: '64kb' }));
// للـ webhook: قبول plain-text و form-encoded أيضاً
app.use('/api/inbound', express.text({ limit: '64kb' }));
app.use('/api/inbound', express.urlencoded({ extended: false, limit: '64kb' }));
// F-03: security headers (without helmet — no network access)
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

// F-06: /go-admin now issues a session token instead of echoing the password in the URL
// X-05: changed from GET to POST so credentials are in the request body, not the URL/query
// (GET params appear in Railway access logs, server logs, and browser history)
// F-01: return JSON token instead of redirect — prevents session token appearing in server logs
app.post('/go-admin', (req, res) => {
  const { email, pass } = req.body || {};
  const ADMIN_EMAIL_ENV = process.env.ADMIN_EMAIL || '';
  if (!safeCompare(pass || '', ADMIN_PASS)) return res.status(401).json({ error: 'Unauthorized' });
  if (ADMIN_EMAIL_ENV && (!email || email.toLowerCase() !== ADMIN_EMAIL_ENV.toLowerCase()))
    return res.status(401).json({ error: 'Unauthorized' });
  const sessionToken = createAdminSession();
  // Return token as JSON — client stores it and navigates to /admin itself
  res.json({ token: sessionToken });
});

app.use(express.static(join(__dirname, '../../frontend')));

const PORT = process.env.PORT || 4000;

// ─── Utils ────────────────────────────────────────────────────────────────────
// F-04: PBKDF2-SHA256 password hashing (memory-hard, GPU-resistant)
// 100,000 iterations per OWASP 2023 recommendation for PBKDF2-HMAC-SHA256
const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_KEYLEN = 32; // 32 bytes = 64 hex chars

/**
 * hashPw(pw, salt) — new: PBKDF2-SHA256 (salt required)
 * Legacy path: salt=null → old SHA-256 single-secret hash (migration only)
 */
function hashPw(pw, salt) {
  if (salt) {
    const pepper = process.env.SECRET || 'mr10x';
    return pbkdf2Sync(pw + pepper, salt, PBKDF2_ITERATIONS, PBKDF2_KEYLEN, 'sha256').toString('hex');
  }
  // legacy (no salt): SHA-256 for checking old unsalted accounts before migration
  return createHash('sha256').update(pw + (process.env.SECRET || 'mr10x')).digest('hex');
}

/**
 * hashPwLegacy(pw, salt) — old SHA-256+salt method used before F-04 fix.
 * Used only in login to migrate existing salted accounts to PBKDF2.
 */
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
      // constant-time length mismatch check
      timingSafeEqual(ba, ba);
      return false;
    }
    return timingSafeEqual(ba, bb);
  } catch {
    return false;
  }
}

// ─── Rate limiting (F-08, F-13) ───────────────────────────────────────────────
const rateLimitStore = new Map(); // key → { count, resetAt }

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

// Cleanup stale rate-limit entries every 5 minutes
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitStore) {
    if (v.resetAt < now) rateLimitStore.delete(k);
  }
}, 5 * 60_000);

// ─── Auth middleware (F-03: use api_token, F-07: subscription check) ──────────
function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'Unauthorized' });
  const seller = db.prepare('SELECT * FROM sellers WHERE api_token = ?').get(token);
  if (!seller) return res.status(401).json({ error: 'Invalid token' });
  if (seller.status === 'pending')  return res.status(403).json({ error: 'pending' });
  if (seller.status === 'rejected') return res.status(403).json({ error: 'rejected' });
  // F-07: enforce subscription expiry
  if (seller.subscription_expires_at && seller.subscription_expires_at < Math.floor(Date.now() / 1000)) {
    return res.status(403).json({ error: 'subscription_expired', message: 'انتهت صلاحية اشتراكك. تواصل مع الدعم للتجديد.' });
  }
  req.seller = seller;
  next();
}

// ─── Admin Auth (F-01: no hardcoded fallback; F-06: session tokens) ──────────
// F-01: ADMIN_PASS must be set — no default fallback
const ADMIN_PASS = process.env.ADMIN_PASS;
if (!ADMIN_PASS) {
  console.error('[FATAL] ADMIN_PASS environment variable is not set. Set it before starting the server.');
  process.exit(1);
}

// In-memory admin sessions: token → { expiresAt }
const adminSessions = new Map();

function createAdminSession() {
  const token = randomBytes(32).toString('hex');
  adminSessions.set(token, { expiresAt: Date.now() + 8 * 60 * 60_000 }); // 8h
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

// Cleanup expired admin sessions every hour
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of adminSessions) {
    if (v.expiresAt < now) adminSessions.delete(k);
  }
}, 60 * 60_000);

function adminMiddleware(req, res, next) {
  // F-01: Accept session token from Authorization header ONLY: "AdminSession <token>"
  // req.query.session removed — tokens must never travel via URL (server log exposure)
  const authHeader = req.headers.authorization || '';
  const sessionToken = authHeader.startsWith('AdminSession ')
    ? authHeader.slice('AdminSession '.length)
    : null;

  if (sessionToken && validateAdminSession(sessionToken)) return next();

  // N-03: x-admin-pass legacy header removed — session tokens only
  return res.status(401).json({ error: 'Unauthorized' });
}

// POST /api/admin/login — exchange password for session token
app.post('/api/admin/login', (req, res) => {
  // N-04: rate limit — 5 attempts per 15 minutes per IP to prevent brute-force
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

// ─── HTML escaping (N-06) ─────────────────────────────────────────────────────
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
  // N-06: escape user-supplied values before inserting into HTML
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
// POST /api/register — إرسال كود التحقق على الإيميل
app.post('/api/register', async (req, res) => {
  const { name, email, password, phone, plan_type } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  // N-07: enforce minimum password length consistently (matches /api/reset-password)
  if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });
  const existing = db.prepare('SELECT id FROM sellers WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  const validPlan = ['plan1', 'plan2', 'plan3'].includes(plan_type) ? plan_type : 'plan2';

  // F-02: cryptographically secure OTP generation
  const code = String(randomInt(100000, 1000000));
  const expiresAt = Math.floor(Date.now() / 1000) + 900; // 15 دقيقة
  const verifyId = randomUUID();

  db.prepare('DELETE FROM email_verifications WHERE email = ?').run(email.toLowerCase());

  // F-05: generate salt and hash with salt
  const salt = generateSalt();
  db.prepare('INSERT INTO email_verifications (id, email, code, name, password, phone, plan_type, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
    .run(verifyId, email.toLowerCase(), code, name, hashPw(password, salt) + ':' + salt, phone || '', validPlan, expiresAt);

  try {
    await sendVerificationEmail(email, name, code);
  } catch (e) {
    console.error('[MAIL ERROR]', e.message);
  }

  res.json({ verify: true, verifyId });
});

// POST /api/verify-email — تأكيد الكود وإنشاء الحساب
app.post('/api/verify-email', (req, res) => {
  const { verifyId, code } = req.body || {};
  if (!verifyId || !code) return res.status(400).json({ error: 'Missing fields' });

  // X-03: rate limit — 10 attempts per 15 minutes per IP to prevent OTP brute-force
  const ip = req.ip;
  if (!rateLimit(`verify-email:${ip}`, 10, 15 * 60_000)) {
    return res.status(429).json({ error: 'Too many attempts. Try again later.' });
  }

  const record = db.prepare('SELECT * FROM email_verifications WHERE id = ?').get(verifyId);
  if (!record) return res.status(404).json({ error: 'انتهت صلاحية الكود أو غير صحيح' });
  if (record.used) return res.status(400).json({ error: 'تم استخدام هذا الكود مسبقاً' });
  if (record.expires_at < Math.floor(Date.now() / 1000)) {
    db.prepare('DELETE FROM email_verifications WHERE id = ?').run(verifyId);
    return res.status(400).json({ error: 'انتهت صلاحية الكود، أعد التسجيل' });
  }
  if (!safeCompare(String(code).trim(), record.code)) {
    return res.status(400).json({ error: 'الكود غير صحيح' });
  }

  const existing = db.prepare('SELECT id FROM sellers WHERE email = ?').get(record.email);
  if (existing) return res.status(409).json({ error: 'البريد الإلكتروني مسجل مسبقاً' });

  // Parse stored "hash:salt" from email_verifications
  let storedHash = record.password;
  let storedSalt = null;
  const colonIdx = record.password.lastIndexOf(':');
  if (colonIdx > 0 && colonIdx < record.password.length - 1) {
    const potentialSalt = record.password.slice(colonIdx + 1);
    if (potentialSalt.length === 32) { // 16-byte hex salt
      storedHash = record.password.slice(0, colonIdx);
      storedSalt = potentialSalt;
    }
  }

  const sellerId = randomUUID();
  const apiToken = randomUUID();
  const sellerPlan = ['plan1', 'plan2', 'plan3'].includes(record.plan_type) ? record.plan_type : 'plan2';
  db.prepare('INSERT INTO sellers (id, name, email, password, salt, phone, status, plan_type, api_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)')
    .run(sellerId, record.name, record.email, storedHash, storedSalt, record.phone, 'pending', sellerPlan, apiToken);

  db.prepare('UPDATE email_verifications SET used = 1 WHERE id = ?').run(verifyId);

  // إرسال إيميل ترحيب بعد إنشاء الحساب
  sendEmail({
    to: record.email,
    subject: 'مرحباً بك في Mr10x 🎉',
    html: `
      <!DOCTYPE html>
      <html lang="ar" dir="rtl">
      <head><meta charset="UTF-8"/></head>
      <body style="margin:0;padding:0;background:#0e0e12;font-family:'Segoe UI',Tahoma,Arial,sans-serif;color:#f4f3ef;direction:rtl;">
        <table width="100%" cellpadding="0" cellspacing="0" style="max-width:580px;margin:40px auto;">
          <tr><td style="background:#17171d;border-radius:18px;border:1px solid rgba(255,255,255,0.07);overflow:hidden;">
            <!-- Header -->
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr><td style="background:linear-gradient(135deg,#1f1f28,#17171d);padding:32px;text-align:center;border-bottom:1px solid rgba(255,255,255,0.07);">
                <div style="font-size:28px;font-weight:900;letter-spacing:-1px;">
                  <span style="color:#f59f0b;">M</span><span style="color:#f59f0b;">r</span><span style="color:#f4f3ef;">10</span><span style="color:#f59f0b;">x</span>
                </div>
              </td></tr>
              <!-- Body -->
              <tr><td style="padding:36px 32px;">
                <div style="font-size:22px;font-weight:800;margin-bottom:12px;">مرحباً، ${record.name} 👋</div>
                <p style="color:#8a8898;line-height:1.7;margin:0 0 24px;">
                  تم إنشاء حسابك في Mr10x بنجاح. سيتم مراجعة طلبك وتفعيل الاشتراك من قِبل الفريق خلال وقت قصير.
                </p>

                <!-- Info box -->
                <table width="100%" cellpadding="0" cellspacing="0" style="background:#1f1f28;border-radius:12px;border:1px solid rgba(255,255,255,0.07);margin-bottom:28px;">
                  <tr><td style="padding:20px 24px;">
                    <div style="color:#8a8898;font-size:12px;font-weight:700;letter-spacing:1px;margin-bottom:12px;">تفاصيل الحساب</div>
                    <div style="margin-bottom:8px;font-size:14px;"><span style="color:#8a8898;">الاسم: </span>${record.name}</div>
                    <div style="margin-bottom:8px;font-size:14px;"><span style="color:#8a8898;">البريد: </span>${record.email}</div>
                    <div style="font-size:14px;"><span style="color:#8a8898;">الحالة: </span><span style="color:#f59f0b;font-weight:700;">قيد المراجعة</span></div>
                  </td></tr>
                </table>

                <!-- Steps -->
                <div style="font-size:14px;font-weight:700;margin-bottom:14px;color:#f4f3ef;">الخطوات التالية:</div>
                <table width="100%" cellpadding="0" cellspacing="0">
                  <tr><td style="padding:0 0 12px;">
                    <div style="display:flex;gap:10px;">
                      <span style="background:rgba(245,159,11,0.12);border:1.5px solid rgba(245,159,11,0.3);color:#f59f0b;border-radius:50%;width:22px;height:22px;display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;margin-left:10px;">١</span>
                      <span style="color:#8a8898;font-size:14px;">انتظر تفعيل الحساب — سيتم ذلك خلال دقائق في أوقات الدوام</span>
                    </div>
                  </td></tr>
                  <tr><td style="padding:0 0 12px;">
                    <span style="background:rgba(245,159,11,0.12);border:1.5px solid rgba(245,159,11,0.3);color:#f59f0b;border-radius:50%;width:22px;height:22px;display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;margin-left:10px;">٢</span>
                    <span style="color:#8a8898;font-size:14px;">ستصلك رسالة إشعار عند التفعيل</span>
                  </td></tr>
                  <tr><td>
                    <span style="background:rgba(245,159,11,0.12);border:1.5px solid rgba(245,159,11,0.3);color:#f59f0b;border-radius:50%;width:22px;height:22px;display:inline-flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;margin-left:10px;">٣</span>
                    <span style="color:#8a8898;font-size:14px;">سجّل الدخول وابدأ استخدام لوحة التحكم</span>
                  </td></tr>
                </table>

                <!-- CTA -->
                <div style="text-align:center;margin-top:32px;">
                  <a href="https://mr10x-otp-production.up.railway.app/index.html" style="display:inline-block;background:#f59f0b;color:#0e0e12;font-weight:800;font-size:15px;padding:14px 32px;border-radius:12px;text-decoration:none;">
                    الذهاب لصفحة تسجيل الدخول
                  </a>
                </div>
              </td></tr>
              <!-- Footer -->
              <tr><td style="padding:20px 32px;text-align:center;border-top:1px solid rgba(255,255,255,0.07);">
                <p style="color:#8a8898;font-size:12px;margin:0;">
                  بحاجة لمساعدة؟
                  <a href="https://wa.me/966500000000" style="color:#f59f0b;text-decoration:none;font-weight:700;">تواصل معنا عبر واتساب</a>
                </p>
                <p style="color:#8a8898;font-size:11px;margin:8px 0 0;">© ${new Date().getFullYear()} Mr10x — جميع الحقوق محفوظة</p>
              </td></tr>
            </table>
          </td></tr>
        </table>
      </body>
      </html>
    `
  }).catch(err => console.error('Welcome email failed:', err));

  res.json({ pending: true });
});

// POST /api/login (F-03: return api_token; F-05: salt-aware hash check)
app.post('/api/login', (req, res) => {
  // X-02: rate limit — 10 attempts per 15 minutes per IP to prevent brute-force
  const ip = req.ip;
  if (!rateLimit(`login:${ip}`, 10, 15 * 60_000)) {
    return res.status(429).json({ error: 'Too many login attempts. Try again later.' });
  }

  const { email, password } = req.body || {};
  const seller = db.prepare('SELECT * FROM sellers WHERE email = ?').get(String(email).toLowerCase());

  if (!seller) return res.status(401).json({ error: 'Invalid credentials' });

  // F-04: try PBKDF2 hash first (new accounts and already-migrated accounts)
  let expectedHash = hashPw(password, seller.salt || null);
  let needsMigration = false;

  if (!safeCompare(expectedHash, seller.password)) {
    if (seller.salt) {
      // Try legacy SHA-256+salt for accounts that existed before the F-04 fix
      const legacyHash = hashPwLegacy(password, seller.salt);
      if (!safeCompare(legacyHash, seller.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
      }
      // Legacy hash matched — will re-hash with PBKDF2 below
      needsMigration = true;
    } else {
      return res.status(401).json({ error: 'Invalid credentials' });
    }
  }

  if (seller.status === 'pending')
    return res.status(403).json({ error: 'pending', message: 'حسابك قيد المراجعة، سنتواصل معك على الواتساب قريباً.' });

  // Lazily migrate: no-salt accounts and legacy SHA-256+salt accounts → PBKDF2
  if (!seller.salt || needsMigration) {
    const newSalt = generateSalt();
    const newHash = hashPw(password, newSalt);
    db.prepare('UPDATE sellers SET password = ?, salt = ? WHERE id = ?').run(newHash, newSalt, seller.id);
  }

  // F-03: return api_token not seller.id
  res.json({
    token: seller.api_token,
    name: seller.name,
    subscription_expires_at: seller.subscription_expires_at || null,
    plan_type: seller.plan_type || 'plan2'
  });
});

// POST /api/forgot-password — طلب إعادة تعيين كلمة المرور (F-11, F-13)
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });

  // F-13: rate limit by IP — 5 requests per 10 minutes
  // N-02: use req.ip (trust proxy=1 set above) instead of parsing X-Forwarded-For manually
  const ip = req.ip;
  if (!rateLimit(`fp:${ip}`, 5, 10 * 60_000)) {
    return res.status(429).json({ error: 'Too many requests. Please wait before trying again.' });
  }

  const seller = db.prepare('SELECT * FROM sellers WHERE email = ?').get(String(email).toLowerCase());
  // F-11: always return ok; never log email not-found
  if (!seller) return res.json({ ok: true });

  const rawToken = randomBytes(32).toString('hex');
  // F-06: store SHA-256 hash of token in DB — raw token only travels in the email link
  const tokenHash = createHash('sha256').update(rawToken).digest('hex');
  const expiresAt = Math.floor(Date.now() / 1000) + 60 * 30; // 30 دقيقة

  db.prepare('INSERT INTO password_resets (id, email, token, expires_at) VALUES (?, ?, ?, ?)')
    .run(randomUUID(), seller.email, tokenHash, expiresAt);

  // F-12: BASE_URL is mandatory — set it in Railway environment variables
  const BASE_URL = process.env.BASE_URL;
  if (!BASE_URL) {
    console.error('[forgot-password] BASE_URL env var not set — reset link cannot be generated');
    return res.json({ ok: true }); // don't expose config error to client
  }
  const resetLink = `${BASE_URL}/reset-password.html?token=${rawToken}`;

  try {
    // N-06: escape seller.name before inserting into HTML
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
});

// POST /api/reset-password — تعيين كلمة مرور جديدة (F-05: salt-aware)
app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

  // F-06: hash the incoming raw token before comparing against stored hash
  const tokenHash = createHash('sha256').update(token).digest('hex');
  const record = db.prepare('SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > ?')
    .get(tokenHash, Math.floor(Date.now() / 1000));

  if (!record) return res.status(400).json({ error: 'الرابط غير صالح أو منتهي الصلاحية' });

  const newSalt = generateSalt();
  const newHash = hashPw(password, newSalt);
  db.prepare('UPDATE sellers SET password = ?, salt = ? WHERE email = ?')
    .run(newHash, newSalt, record.email);
  db.prepare('UPDATE password_resets SET used = 1 WHERE token = ?')
    .run(tokenHash);

  res.json({ ok: true });
});

// GET /api/me — بيانات الحساب الحالي
app.get('/api/me', authMiddleware, (req, res) => {
  const seller = db.prepare('SELECT id, name, email, phone, status, subscription_expires_at, plan_type FROM sellers WHERE id = ?').get(req.seller.id);
  // احسب الأيام المتبقية من subscription_expires_at وأضفها للاستجابة
  // null = اشتراك غير محدود (لا تاريخ انتهاء)، 0 = منتهي
  const now = Math.floor(Date.now() / 1000);
  let subscription_days_left;
  if (!seller.subscription_expires_at) {
    subscription_days_left = null; // غير محدود
  } else if (seller.subscription_expires_at > now) {
    subscription_days_left = Math.ceil((seller.subscription_expires_at - now) / 86400);
  } else {
    subscription_days_left = 0; // منتهي
  }
  // استخرج اسم الخطة من plan_type
  const planNames = { plan1: 'أساسية', plan2: 'احترافية', plan3: 'متقدمة' };
  res.json({ ...seller, subscription_days_left, plan: seller.plan_type });
});

// ─── Admin API ────────────────────────────────────────────────────────────────
app.get('/api/admin/sellers', adminMiddleware, (req, res) => {
  const sellers = db.prepare('SELECT id, name, email, phone, status, created_at, subscription_expires_at, plan_type FROM sellers ORDER BY created_at DESC').all();
  res.json(sellers);
});

app.patch('/api/admin/sellers/:id/approve', adminMiddleware, (req, res) => {
  db.prepare('UPDATE sellers SET status = ? WHERE id = ?').run('active', req.params.id);
  res.json({ ok: true });
});

app.patch('/api/admin/sellers/:id/reject', adminMiddleware, (req, res) => {
  db.prepare('UPDATE sellers SET status = ? WHERE id = ?').run('rejected', req.params.id);
  res.json({ ok: true });
});

app.delete('/api/admin/sellers/:id', adminMiddleware, (req, res) => {
  db.prepare('DELETE FROM sellers WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.patch('/api/admin/sellers/:id/subscription', adminMiddleware, (req, res) => {
  const { expires_at } = req.body || {};
  const ts = expires_at ? Math.floor(new Date(expires_at).getTime() / 1000) : null;
  db.prepare('UPDATE sellers SET subscription_expires_at = ? WHERE id = ?').run(ts, req.params.id);
  res.json({ ok: true });
});

app.patch('/api/admin/sellers/:id/plan', adminMiddleware, (req, res) => {
  const { plan_type } = req.body || {};
  if (!['plan1', 'plan2', 'plan3'].includes(plan_type))
    return res.status(400).json({ error: 'plan_type يجب أن يكون plan1 أو plan2 أو plan3' });
  db.prepare('UPDATE sellers SET plan_type = ? WHERE id = ?').run(plan_type, req.params.id);
  res.json({ ok: true });
});

app.get('/api/admin/stats', adminMiddleware, (req, res) => {
  const totalSellers     = db.prepare("SELECT COUNT(*) as n FROM sellers").get().n;
  const activeSellers    = db.prepare("SELECT COUNT(*) as n FROM sellers WHERE status = 'active'").get().n;
  const pendingSellers   = db.prepare("SELECT COUNT(*) as n FROM sellers WHERE status = 'pending'").get().n;
  const totalMailboxes   = db.prepare("SELECT COUNT(*) as n FROM mailboxes").get().n;
  const totalSlots       = db.prepare("SELECT COUNT(*) as n FROM slots").get().n;
  const totalCodes       = db.prepare("SELECT COUNT(*) as n FROM codes").get().n;
  const codesViewed      = db.prepare("SELECT COUNT(*) as n FROM codes WHERE viewed = 1").get().n;
  const now              = Math.floor(Date.now() / 1000);
  const activeSubs       = db.prepare("SELECT COUNT(*) as n FROM sellers WHERE subscription_expires_at IS NOT NULL AND subscription_expires_at > ?").get(now).n;
  res.json({ totalSellers, activeSellers, pendingSellers, totalMailboxes, totalSlots, totalCodes, codesViewed, activeSubs });
});

// ─── Mailboxes ─────────────────────────────────────────────────────────────────
// ─── Gmail OAuth Routes ────────────────────────────────────────────────────────

// Start OAuth — requires seller Bearer auth
// Returns JSON { url } so the frontend JS can do window.location.href = url
app.get('/api/auth/gmail/start', authMiddleware, (req, res) => {
  if (!gmailEnabled()) return res.status(503).json({ error: 'Gmail OAuth not configured' });
  const { mailbox_id } = req.query;
  if (!mailbox_id) return res.status(400).json({ error: 'mailbox_id required' });

  const mailbox = db.prepare('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?')
    .get(mailbox_id, req.seller.id);
  if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

  const state = makeOAuthState(mailbox_id, req.seller.id);
  res.json({ url: getAuthUrl(state) });
});

// OAuth callback — from Google, no Bearer auth
app.get('/api/auth/gmail/callback', async (req, res) => {
  if (!gmailEnabled()) return res.status(503).send('Gmail OAuth not configured');
  const { code, state, error } = req.query;

  if (error) {
    return res.redirect(`/index.html?gmail_error=${encodeURIComponent(error)}`);
  }
  if (!code || !state) {
    return res.redirect('/index.html?gmail_error=missing_params');
  }

  const parsed = parseOAuthState(state);
  if (!parsed) {
    return res.redirect('/index.html?gmail_error=invalid_state');
  }

  const { mailboxId, sellerId } = parsed;

  // Verify mailbox still belongs to this seller
  const mailbox = db.prepare('SELECT id, email FROM mailboxes WHERE id = ? AND seller_id = ?')
    .get(mailboxId, sellerId);
  if (!mailbox) {
    return res.redirect('/?gmail_error=mailbox_not_found');
  }

  try {
    const tokens = await exchangeCode(code);
    const now = Math.floor(Date.now() / 1000);
    const expiry = now + (tokens.expires_in || 3600);

    // Get the connected Gmail address
    let gmailEmail = null;
    try { gmailEmail = await getGmailAddress(tokens.access_token); } catch {}

    db.prepare(`
      UPDATE mailboxes
      SET gmail_refresh_token = ?, gmail_access_token = ?, gmail_token_expiry = ?,
          gmail_email = ?, gmail_last_sync_ts = ?, status = 'active', last_error = NULL
      WHERE id = ?
    `).run(
      tokens.refresh_token,
      tokens.access_token,
      expiry,
      gmailEmail || mailbox.email,
      now,
      mailboxId
    );

    // Redirect back to the seller dashboard
    res.redirect('/index.html?gmail_connected=1');
  } catch (err) {
    console.error('[Gmail OAuth] callback error:', err.message);
    res.redirect(`/index.html?gmail_error=${encodeURIComponent('فشل الاتصال بـ Gmail')}`);
  }
});

// Disconnect Gmail from a mailbox
app.post('/api/mailboxes/:id/gmail-disconnect', authMiddleware, (req, res) => {
  const mailbox = db.prepare('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?')
    .get(req.params.id, req.seller.id);
  if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

  db.prepare(`
    UPDATE mailboxes
    SET gmail_refresh_token = NULL, gmail_access_token = NULL,
        gmail_token_expiry = NULL, gmail_email = NULL, gmail_last_sync_ts = NULL,
        status = 'active'
    WHERE id = ?
  `).run(req.params.id);

  res.json({ ok: true });
});

// ─── Mailboxes ─────────────────────────────────────────────────────────────────

app.get('/api/mailboxes', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT id, email, label, status, last_sync, last_error, webhook_token,
           gmail_email,
           CASE WHEN gmail_refresh_token IS NOT NULL THEN 1 ELSE 0 END as gmail_connected
    FROM mailboxes WHERE seller_id = ?
  `).all(req.seller.id);
  res.json(rows);
});

// إضافة صندوق جديد — webhook فقط، لا كلمة مرور
app.post('/api/mailboxes', authMiddleware, (req, res) => {
  const { email, label } = req.body || {};
  if (!email) return res.status(400).json({ error: 'البريد الإلكتروني مطلوب' });
  const mailboxCount = db.prepare('SELECT COUNT(*) as cnt FROM mailboxes WHERE seller_id = ?').get(req.seller.id);
  if (mailboxCount.cnt >= 500) return res.status(400).json({ error: 'تعذّر إضافة صندوق البريد، يرجى التواصل مع الدعم.' });
  const id = randomUUID();
  const webhookToken = randomUUID();
  db.prepare(`INSERT INTO mailboxes (id, seller_id, email, imap_host, imap_port, password, label, status, webhook_token)
    VALUES (?, ?, ?, '', 993, '', ?, 'active', ?)`)
    .run(id, req.seller.id, email.toLowerCase().trim(), label || '', webhookToken);
  res.json({ id, email, label: label || '', status: 'active', webhook_token: webhookToken });
});

app.delete('/api/mailboxes/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM mailboxes WHERE id = ? AND seller_id = ?').run(req.params.id, req.seller.id);
  res.json({ ok: true });
});

// ─── Inbound Webhook ───────────────────────────────────────────────────────────
// Gmail / أي خدمة توجيه تُرسل الإيميل الوارد هنا كـ POST
// محتوى الطلب: نص الإيميل (plain-text أو HTML) في body.text / body.html / raw body
app.post('/api/inbound/:token', (req, res) => {
  const mailbox = db.prepare('SELECT * FROM mailboxes WHERE webhook_token = ?').get(req.params.token);
  if (!mailbox) return res.status(404).json({ error: 'Invalid token' });

  // استخراج نص الإيميل من أي صيغة ترسلها خدمة التوجيه
  let subject = '';
  let body = '';

  const ct = (req.headers['content-type'] || '').toLowerCase();

  if (ct.includes('application/json')) {
    // بعض الخدمات ترسل JSON: { subject, text, html, body, plain, ... }
    const p = req.body || {};
    subject = String(p.subject || p.Subject || '');
    body = String(p.text || p.plain || p.body || p.html || '');
  } else {
    // plain text / form-encoded / raw
    body = String(req.body?.text || req.body?.body || '');
    subject = String(req.body?.subject || '');
  }

  // إذا body فارغ ولكن المحتوى الخام موجود (content-type: text/plain)
  if (!body && typeof req.body === 'string') {
    body = req.body;
  }

  const code = extractCode(subject, body);

  if (!code) {
    console.log(`[Webhook] لا كود في إيميل لصندوق ${mailbox.email}`);
    return res.json({ ok: true, extracted: false });
  }

  // إيجاد السلوتس المرتبطة بهذا الصندوق
  const slots = db.prepare('SELECT * FROM slots WHERE mailbox_id = ?').all(mailbox.id);
  const receivedTs = Math.floor(Date.now() / 1000);

  for (const slot of slots) {
    // تجنب التكرار
    const exists = db.prepare(
      'SELECT id FROM codes WHERE slot_id = ? AND code = ? AND received_at > ?'
    ).get(slot.id, code, receivedTs - 60);
    if (exists) continue;

    db.prepare(`
      INSERT INTO codes (id, slot_id, code, email_from, email_subj, received_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      randomUUID(), slot.id, code,
      String(req.body?.from || req.body?.sender || '').toLowerCase().slice(0, 200),
      subject.slice(0, 200),
      receivedTs,
      receivedTs + 10 * 60 // ينتهي بعد 10 دقائق
    );

    console.log(`[Webhook] 🔑 كود جديد ${code} → slot ${slot.id}`);
  }

  // تحديث last_sync
  db.prepare("UPDATE mailboxes SET last_sync = ?, status = 'active', last_error = NULL WHERE id = ?")
    .run(receivedTs, mailbox.id);

  res.json({ ok: true, extracted: true, code });
});

// ─── Slots ────────────────────────────────────────────────────────────────────
app.get('/api/slots', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT s.id, s.label, s.token, s.mailbox_id, s.created_at,
           s.account_email,
           m.email as mailbox_email,
           (SELECT code FROM codes WHERE slot_id = s.id ORDER BY received_at DESC LIMIT 1) as latest_code
    FROM slots s JOIN mailboxes m ON m.id = s.mailbox_id
    WHERE s.seller_id = ? ORDER BY s.created_at DESC`)
    .all(req.seller.id);
  res.json(rows);
});

app.post('/api/slots', authMiddleware, (req, res) => {
  const { mailbox_id, label, count = 1, account_email = '', account_password = '' } = req.body || {};
  if (!mailbox_id || !label) return res.status(400).json({ error: 'mailbox_id and label required' });
  const mailbox = db.prepare('SELECT id FROM mailboxes WHERE id = ? AND seller_id = ?').get(mailbox_id, req.seller.id);
  if (!mailbox) return res.status(404).json({ error: 'Mailbox not found' });

  const seller = db.prepare('SELECT plan_type FROM sellers WHERE id = ?').get(req.seller.id);
  const planType = seller?.plan_type || 'plan2';
  if (planType === 'plan1') {
    const existingCount = db.prepare('SELECT COUNT(*) as n FROM slots WHERE seller_id = ?').get(req.seller.id).n;
    if (existingCount >= 1)
      return res.status(403).json({ error: 'plan_limit', message: 'باقتك تسمح بتطبيق واحد فقط. يرجى الترقية للباقة الثانية أو الثالثة.' });
  }

  const created = [];
  // N-08: lower max bulk slots from 100 → 10 to limit DoS potential
  const n = Math.min(Number(count) || 1, 10);
  // N-01: encrypt account_password before storing
  const encryptedAccountPassword = account_password ? encryptPassword(account_password) : '';
  for (let i = 0; i < n; i++) {
    const id = randomUUID();
    const token = randomBytes(16).toString('hex'); // F-02: cryptographically secure slot token
    db.prepare('INSERT INTO slots (id, seller_id, mailbox_id, label, token, account_email, account_password, account_password_encrypted) VALUES (?, ?, ?, ?, ?, ?, ?, ?)')
      .run(id, req.seller.id, mailbox_id, label, token, account_email, encryptedAccountPassword, encryptedAccountPassword ? 1 : 0);
    created.push({ id, token, label, account_email });
  }
  res.json(created);
});

app.patch('/api/slots/:id', authMiddleware, (req, res) => {
  const { account_email, account_password, label } = req.body || {};
  const slot = db.prepare('SELECT id FROM slots WHERE id = ? AND seller_id = ?').get(req.params.id, req.seller.id);
  if (!slot) return res.status(404).json({ error: 'Slot not found' });
  if (account_email !== undefined)
    db.prepare('UPDATE slots SET account_email = ? WHERE id = ?').run(account_email, req.params.id);
  if (account_password !== undefined) {
    // N-01: encrypt before storing
    const enc = account_password ? encryptPassword(account_password) : '';
    db.prepare('UPDATE slots SET account_password = ?, account_password_encrypted = ? WHERE id = ?')
      .run(enc, enc ? 1 : 0, req.params.id);
  }
  if (label !== undefined)
    db.prepare('UPDATE slots SET label = ? WHERE id = ?').run(label, req.params.id);
  res.json({ ok: true });
});

app.patch('/api/slots/:id/reset', authMiddleware, (req, res) => {
  const slot = db.prepare('SELECT id FROM slots WHERE id = ? AND seller_id = ?').get(req.params.id, req.seller.id);
  if (!slot) return res.status(404).json({ error: 'Slot not found' });
  db.prepare('UPDATE slots SET code_attempts = 0 WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

app.delete('/api/slots/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM slots WHERE id = ? AND seller_id = ?').run(req.params.id, req.seller.id);
  res.json({ ok: true });
});

// ─── Customer endpoint (public) ───────────────────────────────────────────────
// GET /api/slot/:token — F-08: rate limited (10 req/min per IP)
app.get('/api/slot/:token', (req, res) => {
  // N-02: use req.ip (trust proxy=1 set above)
  const ip = req.ip;
  if (!rateLimit(`slot:${ip}`, 10, 60_000)) {
    return res.status(429).json({ error: 'Too many requests.' });
  }
  const slot = db.prepare('SELECT * FROM slots WHERE token = ?').get(req.params.token);
  if (!slot) return res.status(404).json({ error: 'Invalid link' });
  // N-08: account_password returned decrypted — slot token is the customer's auth credential
  const rawPass = slot.account_password
    ? (slot.account_password_encrypted ? decryptPassword(slot.account_password) : slot.account_password)
    : '';
  res.json({
    label: slot.label,
    account_email: slot.account_email || '',
    account_password: rawPass,
    attempts_left: Math.max(0, 2 - (slot.code_attempts || 0))
  });
});

// GET /api/code/:token — جلب آخر كود
app.get('/api/code/:token', (req, res) => {
  // N-05: rate limit — 20 req/min per IP (prevent enumeration/scraping)
  const ip = req.ip;
  if (!rateLimit(`code:${ip}`, 20, 60_000)) {
    return res.status(429).json({ error: 'Too many requests.' });
  }

  const slot = db.prepare('SELECT * FROM slots WHERE token = ?').get(req.params.token);
  if (!slot) return res.status(404).json({ error: 'Invalid link' });

  // N-08: decrypt account_password for the customer-facing response
  const rawPass = slot.account_password
    ? (slot.account_password_encrypted ? decryptPassword(slot.account_password) : slot.account_password)
    : '';
  const attempts = slot.code_attempts || 0;
  if (attempts >= 2) {
    return res.json({
      status: 'exhausted',
      label: slot.label,
      account_email: slot.account_email || '',
      account_password: rawPass
    });
  }

  const code = db.prepare(`
    SELECT code, received_at, expires_at FROM codes
    WHERE slot_id = ? AND expires_at > ?
    ORDER BY received_at DESC LIMIT 1`)
    .get(slot.id, Math.floor(Date.now() / 1000));

  if (!code) return res.json({ status: 'waiting', label: slot.label, account_email: slot.account_email || '', account_password: rawPass });

  db.prepare('UPDATE slots SET code_attempts = code_attempts + 1 WHERE id = ?').run(slot.id);
  db.prepare('UPDATE codes SET viewed = 1 WHERE slot_id = ? AND code = ?').run(slot.id, code.code);

  res.json({
    status: 'ready',
    code: code.code,
    label: slot.label,
    expires_in: code.expires_at - Math.floor(Date.now() / 1000),
    attempts_left: Math.max(0, 2 - (attempts + 1)),
    account_email: slot.account_email || '',
    account_password: rawPass
  });
});

// ─── Polling ──────────────────────────────────────────────────────────────────
pollAll();

// Gmail polling — كل 60 ثانية
if (gmailEnabled()) {
  // Initial poll after 10 seconds (let server warm up)
  setTimeout(() => pollGmailMailboxes(db), 10_000);
  setInterval(() => pollGmailMailboxes(db), 60_000);
  console.log('[Gmail] Polling enabled — every 60s');
} else {
  console.log('[Gmail] OAuth not configured (GOOGLE_CLIENT_ID/SECRET/REDIRECT_URI missing)');
}

// TEMP: one-shot email update — remove after use
app.post('/api/admin/update-seller-email', adminMiddleware, (req, res) => {
  const { old_email, new_email } = req.body || {};
  if (!old_email || !new_email) return res.status(400).json({ error: 'old_email and new_email required' });
  const result = db.prepare('UPDATE sellers SET email = ? WHERE email = ?').run(new_email, old_email);
  res.json({ changes: result.changes });
});

app.listen(PORT, () => {
  console.log(`Mr10x OTP Backend running on port ${PORT}`);
});
