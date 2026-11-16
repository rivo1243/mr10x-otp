import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { randomUUID } from 'node:crypto';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { join, dirname } from 'node:path';
import db from './db.js';
import { guessHost, testConnection } from './imap.js';
import { pollAll } from './poller.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const app = express();
app.use(cors());
app.use(express.json());

// ─── Serve Frontend ───────────────────────────────────────────────────────────
// الصفحة الرئيسية → landing.html (يجب أن يكون قبل express.static)
app.get('/', (req, res) => {
  res.sendFile(join(__dirname, '../../frontend/landing.html'));
});

app.use(express.static(join(__dirname, '../../frontend')));

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
  if (seller.status === 'pending') return res.status(403).json({ error: 'pending' });
  if (seller.status === 'rejected') return res.status(403).json({ error: 'rejected' });
  req.seller = seller;
  next();
}

// ─── Admin Auth ───────────────────────────────────────────────────────────────
const ADMIN_PASS = process.env.ADMIN_PASS || 'mr10x-admin-2024';

function adminMiddleware(req, res, next) {
  const pass = req.headers['x-admin-pass'] || req.query.pass;
  if (pass !== ADMIN_PASS) return res.status(401).json({ error: 'Unauthorized' });
  next();
}

// ─── Mailer (Gmail SMTP) ──────────────────────────────────────────────────────
const RESEND_API_KEY = process.env.RESEND_API_KEY;

async function sendEmail({ to, subject, html }) {
  if (!RESEND_API_KEY) {
    console.error(`[MAIL ERROR] RESEND_API_KEY not set — cannot send email to ${to}`);
    throw new Error('RESEND_API_KEY not configured');
  }

  console.log(`[MAIL] attempting to send to ${to} via Resend`);

  const res = await fetch('https://api.resend.com/emails', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${RESEND_API_KEY}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      from: 'Mr10x <onboarding@resend.dev>',
      to,
      subject,
      html
    })
  });

  if (!res.ok) {
    const err = await res.text();
    console.error(`[MAIL ERROR] Resend responded ${res.status}: ${err}`);
    throw new Error(`Resend error ${res.status}: ${err}`);
  }

  console.log(`[MAIL] sent to ${to} via Resend ✓`);
}

async function sendVerificationEmail(toEmail, toName, code) {
  await sendEmail({
    to: toEmail,
    subject: 'كود تأكيد التسجيل في Mr10x',
    html: `
      <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 480px; margin: auto;">
        <h2 style="color: #7c3aed;">مرحباً ${toName} 👋</h2>
        <p>شكراً لتسجيلك في <strong>Mr10x</strong>. أدخل الكود التالي لتأكيد بريدك الإلكتروني:</p>
        <div style="background: #1a1a2e; border: 2px solid #7c3aed; border-radius: 12px; padding: 24px; text-align: center; margin: 24px 0;">
          <span style="font-size: 36px; font-weight: bold; color: #a855f7; letter-spacing: 8px;">${code}</span>
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
  const { name, email, password, phone } = req.body || {};
  if (!name || !email || !password) return res.status(400).json({ error: 'Missing fields' });
  const existing = db.prepare('SELECT id FROM sellers WHERE email = ?').get(email.toLowerCase());
  if (existing) return res.status(409).json({ error: 'Email already registered' });

  // توليد كود 6 أرقام
  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expiresAt = Math.floor(Date.now() / 1000) + 900; // 15 دقيقة
  const verifyId = randomUUID();

  // حذف أي طلبات سابقة لنفس الإيميل
  db.prepare('DELETE FROM email_verifications WHERE email = ?').run(email.toLowerCase());

  db.prepare('INSERT INTO email_verifications (id, email, code, name, password, phone, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(verifyId, email.toLowerCase(), code, name, hashPw(password), phone || '', expiresAt);

  try {
    await sendVerificationEmail(email, name, code);
  } catch (e) {
    console.error('[MAIL ERROR]', e.message);
    // لا نوقف العملية إذا فشل الإيميل — نكمل
  }

  res.json({ verify: true, verifyId });
});

// POST /api/verify-email — تأكيد الكود وإنشاء الحساب
app.post('/api/verify-email', (req, res) => {
  const { verifyId, code } = req.body || {};
  if (!verifyId || !code) return res.status(400).json({ error: 'Missing fields' });

  const record = db.prepare('SELECT * FROM email_verifications WHERE id = ?').get(verifyId);
  if (!record) return res.status(404).json({ error: 'انتهت صلاحية الكود أو غير صحيح' });
  if (record.used) return res.status(400).json({ error: 'تم استخدام هذا الكود مسبقاً' });
  if (record.expires_at < Math.floor(Date.now() / 1000)) {
    db.prepare('DELETE FROM email_verifications WHERE id = ?').run(verifyId);
    return res.status(400).json({ error: 'انتهت صلاحية الكود، أعد التسجيل' });
  }
  if (record.code !== String(code).trim()) {
    return res.status(400).json({ error: 'الكود غير صحيح' });
  }

  // تأكيد ناجح — إنشاء الحساب
  const existing = db.prepare('SELECT id FROM sellers WHERE email = ?').get(record.email);
  if (existing) return res.status(409).json({ error: 'البريد الإلكتروني مسجل مسبقاً' });

  const sellerId = randomUUID();
  db.prepare('INSERT INTO sellers (id, name, email, password, phone, status) VALUES (?, ?, ?, ?, ?, ?)')
    .run(sellerId, record.name, record.email, record.password, record.phone, 'pending');

  // وضع علامة مستخدم
  db.prepare('UPDATE email_verifications SET used = 1 WHERE id = ?').run(verifyId);

  res.json({ pending: true });
});

app.post('/api/login', (req, res) => {
  const { email, password } = req.body || {};
  const seller = db.prepare('SELECT * FROM sellers WHERE email = ?').get(String(email).toLowerCase());
  if (!seller || seller.password !== hashPw(password))
    return res.status(401).json({ error: 'Invalid credentials' });
  if (seller.status === 'pending')
    return res.status(403).json({ error: 'pending', message: 'حسابك قيد المراجعة، سنتواصل معك على الواتساب قريباً.' });
  res.json({ token: seller.id, name: seller.name, subscription_expires_at: seller.subscription_expires_at || null });
});

// POST /api/forgot-password — طلب إعادة تعيين كلمة المرور
app.post('/api/forgot-password', async (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });

  console.log(`[forgot-password] request for: ${email}`);

  const seller = db.prepare('SELECT * FROM sellers WHERE email = ?').get(String(email).toLowerCase());
  // نرجع نجاح دائماً حتى لا نكشف وجود الإيميل
  if (!seller) {
    console.log(`[forgot-password] email not found: ${email}`);
    return res.json({ ok: true });
  }

  const token = randomUUID().replace(/-/g, '');
  const expiresAt = Math.floor(Date.now() / 1000) + 60 * 30; // 30 دقيقة

  db.prepare('INSERT INTO password_resets (id, email, token, expires_at) VALUES (?, ?, ?, ?)')
    .run(randomUUID(), seller.email, token, expiresAt);

  const BASE_URL = process.env.BASE_URL || 'https://mr10x-otp-production.up.railway.app';
  const resetLink = `${BASE_URL}/reset-password.html?token=${token}`;

  try {
    await sendEmail({
      to: seller.email,
      subject: 'إعادة تعيين كلمة المرور — Mr10x',
      html: `
        <div dir="rtl" style="font-family: Arial, sans-serif; max-width: 480px; margin: auto; background:#0f0f1a; color:#e2e8f0; padding:32px; border-radius:12px;">
          <h2 style="color:#a855f7; margin-bottom:8px;">Mr10x</h2>
          <p>مرحباً ${seller.name}،</p>
          <p>طلبت إعادة تعيين كلمة مرورك. اضغط الزر أدناه:</p>
          <a href="${resetLink}" style="display:inline-block;margin:20px 0;padding:14px 28px;background:#7c3aed;color:#fff;text-decoration:none;border-radius:8px;font-weight:bold;">إعادة تعيين كلمة المرور</a>
          <p style="color:#94a3b8;font-size:13px;">الرابط صالح لمدة 30 دقيقة فقط. إذا لم تطلب هذا، تجاهل الرسالة.</p>
        </div>
      `
    });
    console.log(`[forgot-password] email sent to: ${seller.email}`);
  } catch (mailErr) {
    console.error(`[forgot-password] mail error:`, mailErr.message);
  }

  res.json({ ok: true });
});

// POST /api/reset-password — تعيين كلمة مرور جديدة
app.post('/api/reset-password', (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).json({ error: 'Missing fields' });
  if (password.length < 6) return res.status(400).json({ error: 'كلمة المرور يجب أن تكون 6 أحرف على الأقل' });

  const record = db.prepare('SELECT * FROM password_resets WHERE token = ? AND used = 0 AND expires_at > ?')
    .get(token, Math.floor(Date.now() / 1000));

  if (!record) return res.status(400).json({ error: 'الرابط غير صالح أو منتهي الصلاحية' });

  db.prepare('UPDATE sellers SET password = ? WHERE email = ?')
    .run(hashPw(password), record.email);
  db.prepare('UPDATE password_resets SET used = 1 WHERE token = ?')
    .run(token);

  res.json({ ok: true });
});

// GET /api/me — بيانات الحساب الحالي
app.get('/api/me', authMiddleware, (req, res) => {
  const seller = db.prepare('SELECT id, name, email, phone, status, subscription_expires_at FROM sellers WHERE id = ?').get(req.seller.id);
  res.json(seller);
});

// ─── Admin API ────────────────────────────────────────────────────────────────
// GET /api/admin/sellers — قائمة البائعين
app.get('/api/admin/sellers', adminMiddleware, (req, res) => {
  const sellers = db.prepare('SELECT id, name, email, phone, status, created_at, subscription_expires_at FROM sellers ORDER BY created_at DESC').all();
  res.json(sellers);
});

// PATCH /api/admin/sellers/:id/approve — قبول بائع
app.patch('/api/admin/sellers/:id/approve', adminMiddleware, (req, res) => {
  db.prepare('UPDATE sellers SET status = ? WHERE id = ?').run('active', req.params.id);
  res.json({ ok: true });
});

// PATCH /api/admin/sellers/:id/reject — رفض / تعليق بائع
app.patch('/api/admin/sellers/:id/reject', adminMiddleware, (req, res) => {
  db.prepare('UPDATE sellers SET status = ? WHERE id = ?').run('rejected', req.params.id);
  res.json({ ok: true });
});

// DELETE /api/admin/sellers/:id — حذف بائع
app.delete('/api/admin/sellers/:id', adminMiddleware, (req, res) => {
  db.prepare('DELETE FROM sellers WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// PATCH /api/admin/sellers/:id/subscription — تعيين تاريخ انتهاء الاشتراك
app.patch('/api/admin/sellers/:id/subscription', adminMiddleware, (req, res) => {
  const { expires_at } = req.body || {};
  const ts = expires_at ? Math.floor(new Date(expires_at).getTime() / 1000) : null;
  db.prepare('UPDATE sellers SET subscription_expires_at = ? WHERE id = ?').run(ts, req.params.id);
  res.json({ ok: true });
});

// GET /api/admin/stats — إحصائيات عامة للأدمن
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
app.get('/api/mailboxes', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT id, email, imap_host, imap_port, label, status, last_sync, last_error FROM mailboxes WHERE seller_id = ?')
    .all(req.seller.id);
  res.json(rows);
});

app.post('/api/mailboxes', authMiddleware, async (req, res) => {
  const { email, password, host, port, label } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
  // حد خفي: 500 صندوق بريد لكل بائع
  const mailboxCount = db.prepare('SELECT COUNT(*) as cnt FROM mailboxes WHERE seller_id = ?').get(req.seller.id);
  if (mailboxCount.cnt >= 500) return res.status(400).json({ error: 'تعذّر إضافة صندوق البريد، يرجى التواصل مع الدعم.' });
  const imapHost = host || guessHost(email);
  const imapPort = Number(port) || 993;
  try {
    await testConnection(email, password, imapHost, imapPort);
  } catch (e) {
    const msg = e.message;
    let arabicError;
    if (msg === 'AUTH_FAIL:GMAIL') {
      arabicError = 'فشل تسجيل الدخول — Gmail يطلب App Password (كلمة مرور التطبيقات) وليس كلمة مرورك العادية. اذهب إلى myaccount.google.com/apppasswords وأنشئ كلمة مرور جديدة واستخدمها هنا.';
    } else if (msg === 'AUTH_FAIL:OUTLOOK') {
      arabicError = 'فشل تسجيل الدخول — تأكد من تفعيل IMAP في إعدادات Outlook، وأنك تستخدم كلمة المرور الصحيحة.';
    } else if (msg === 'AUTH_FAIL:YAHOO') {
      arabicError = 'فشل تسجيل الدخول — Yahoo يطلب App Password. اذهب إلى إعدادات الحساب في Yahoo وأنشئ كلمة مرور للتطبيقات.';
    } else if (msg === 'AUTH_FAIL:GENERIC') {
      arabicError = 'كلمة المرور أو الإيميل غير صحيحة. تأكد من بيانات الدخول.';
    } else if (msg === 'CONN_FAIL') {
      arabicError = 'تعذّر الاتصال بالسيرفر — تأكد من صحة عنوان IMAP والـ Port.';
    } else {
      arabicError = `فشل الاتصال: ${msg}`;
    }
    return res.status(400).json({ error: arabicError });
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

  const created = [];
  const n = Math.min(Number(count) || 1, 100);
  for (let i = 0; i < n; i++) {
    const id = randomUUID();
    const token = randomUUID().replace(/-/g, '');
    db.prepare('INSERT INTO slots (id, seller_id, mailbox_id, label, token, account_email, account_password) VALUES (?, ?, ?, ?, ?, ?, ?)')
      .run(id, req.seller.id, mailbox_id, label, token, account_email, account_password);
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
  if (account_password !== undefined)
    db.prepare('UPDATE slots SET account_password = ? WHERE id = ?').run(account_password, req.params.id);
  if (label !== undefined)
    db.prepare('UPDATE slots SET label = ? WHERE id = ?').run(label, req.params.id);
  res.json({ ok: true });
});

app.delete('/api/slots/:id', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM slots WHERE id = ? AND seller_id = ?').run(req.params.id, req.seller.id);
  res.json({ ok: true });
});

// ─── Customer endpoint (public) ───────────────────────────────────────────────
// GET /api/slot/:token — بيانات السلوت (الإيميل + الباسورد + الحالة)
app.get('/api/slot/:token', (req, res) => {
  const slot = db.prepare('SELECT * FROM slots WHERE token = ?').get(req.params.token);
  if (!slot) return res.status(404).json({ error: 'Invalid link' });
  res.json({
    label: slot.label,
    account_email: slot.account_email || '',
    account_password: slot.account_password || '',
    attempts_left: Math.max(0, 2 - (slot.code_attempts || 0))
  });
});

// GET /api/code/:token — جلب آخر كود (عند الضغط على الزر)
app.get('/api/code/:token', (req, res) => {
  const slot = db.prepare('SELECT * FROM slots WHERE token = ?').get(req.params.token);
  if (!slot) return res.status(404).json({ error: 'Invalid link' });

  // التحقق من حد المحاولات (2 محاولة فقط)
  const attempts = slot.code_attempts || 0;
  if (attempts >= 2) {
    return res.json({
      status: 'exhausted',
      label: slot.label,
      account_email: slot.account_email || '',
      account_password: slot.account_password || ''
    });
  }

  const code = db.prepare(`
    SELECT code, received_at, expires_at FROM codes
    WHERE slot_id = ? AND expires_at > ?
    ORDER BY received_at DESC LIMIT 1`)
    .get(slot.id, Math.floor(Date.now() / 1000));

  if (!code) return res.json({ status: 'waiting', label: slot.label });

  // زيادة عداد المحاولات + وضع علامة شُوهد
  db.prepare('UPDATE slots SET code_attempts = code_attempts + 1 WHERE id = ?').run(slot.id);
  db.prepare('UPDATE codes SET viewed = 1 WHERE slot_id = ? AND code = ?').run(slot.id, code.code);

  res.json({
    status: 'ready',
    code: code.code,
    label: slot.label,
    expires_in: code.expires_at - Math.floor(Date.now() / 1000),
    attempts_left: Math.max(0, 2 - (attempts + 1))
  });
});

// ─── Polling ──────────────────────────────────────────────────────────────────
pollAll(); // يبدأ connections IDLE الفورية

app.listen(PORT, () => {
  console.log(`Mr10x OTP Backend running on port ${PORT}`);
});

