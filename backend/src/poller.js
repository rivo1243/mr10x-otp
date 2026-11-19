import db from './db.js';
import { ImapFlow } from 'imapflow';
import { convert } from 'html-to-text';
import { extractCode } from './extract.js';
import { randomUUID } from 'node:crypto';
import { decryptPassword } from './crypto-utils.js';

// ── خريطة connections الحية: mailbox_id → { client, busy }
const liveConns = new Map();

// ── عداد إعادة المحاولة لكل صندوق: mailbox_id → attempt count
const retryCount = new Map();

// ── احسب وقت الانتظار حسب عدد المحاولات (exponential backoff)
function getRetryDelay(id) {
  const attempt = (retryCount.get(id) || 0) + 1;
  retryCount.set(id, attempt);
  // 10s, 30s, 60s, 5min, 5min, 5min...
  const delays = [10_000, 30_000, 60_000, 300_000];
  return delays[Math.min(attempt - 1, delays.length - 1)];
}

// ── استخراج نص الرسالة ────────────────────────────────────────────────────
function extractText(msg) {
  const parts = msg.bodyParts;
  if (!parts) return '';
  let plain = '', html = '';
  for (const [key, buf] of parts) {
    const k = String(key).toLowerCase();
    if (k === 'text' || k === '1') plain += buf.toString('utf8');
    else if (k === 'html' || k === '2') html += buf.toString('utf8');
  }
  if (plain) return plain;
  if (html) return convert(html, { wordwrap: false });
  return '';
}

// ── معالجة رسالة واحدة وإدراج الكود لو وُجد ─────────────────────────────
function processMsg(mailbox, msg) {
  const code = extractCode(msg.subject, msg.body);
  if (!code) return;

  const slots = db.prepare(
    'SELECT * FROM slots WHERE mailbox_id = ? AND seller_id = ?'
  ).all(mailbox.id, mailbox.seller_id);

  const receivedTs = Math.floor(msg.received.getTime() / 1000);

  for (const slot of slots) {
    const exists = db.prepare(
      'SELECT id FROM codes WHERE slot_id = ? AND code = ? AND received_at = ?'
    ).get(slot.id, code, receivedTs);
    if (exists) continue;

    db.prepare(`
      INSERT INTO codes (id, slot_id, code, email_from, email_subj, received_at, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      randomUUID(), slot.id, code,
      msg.from, msg.subject.slice(0, 200),
      receivedTs,
      Math.floor(Date.now() / 1000) + 10 * 60 // ينتهي بعد 10 دقائق
    );

    console.log(`[IMAP] 🔑 كود جديد ${code} → slot ${slot.id}`);
  }
}

// ── فتح connection دائم لصندوق بريد مع IDLE ─────────────────────────────
async function connectMailbox(mailbox) {
  // إذا عنده connection حي نتركه
  const existing = liveConns.get(mailbox.id);
  if (existing) return;

  const client = new ImapFlow({
    host: mailbox.imap_host,
    port: Number(mailbox.imap_port) || 993,
    secure: true,
    // F-04: decrypt stored IMAP password before use
    auth: { user: mailbox.email, pass: decryptPassword(mailbox.password) },
    logger: false,
    // F-10: enforce TLS certificate verification
    tls: { rejectUnauthorized: true }
  });

  liveConns.set(mailbox.id, { client, busy: false });

  client.on('error', (err) => {
    db.prepare("UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?")
      .run(String(err.message).slice(0, 200), mailbox.id);
    liveConns.delete(mailbox.id);
    const delay = getRetryDelay(mailbox.id);
    console.log(`[IMAP] ⚠️ خطأ ${mailbox.email} — إعادة المحاولة بعد ${delay/1000}ث`);
    setTimeout(() => connectMailbox(mailbox), delay);
  });

  try {
    await client.connect();

    // جلب الرسائل اللي وصلت في آخر 5 دقائق عند الاتصال الأول
    await initialFetch(client, mailbox);

    // اتصل بنجاح — صفّر عداد المحاولات
    retryCount.delete(mailbox.id);

    db.prepare("UPDATE mailboxes SET status = 'connected', last_error = NULL WHERE id = ?")
      .run(mailbox.id);

    console.log(`[IMAP] ✅ متصل ${mailbox.email} — IDLE فعّال`);

    // ابدأ حلقة IDLE — تنتظر إشعار من السيرفر
    idleLoop(client, mailbox);

  } catch (err) {
    db.prepare("UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?")
      .run(String(err.message).slice(0, 200), mailbox.id);
    liveConns.delete(mailbox.id);
    const delay = getRetryDelay(mailbox.id);
    console.log(`[IMAP] ❌ فشل الاتصال ${mailbox.email} — إعادة بعد ${delay/1000}ث`);
    setTimeout(() => connectMailbox(mailbox), delay);
  }
}

// ── جلب أولي لرسائل آخر 5 دقائق ─────────────────────────────────────────
async function initialFetch(client, mailbox) {
  const lock = await client.getMailboxLock('INBOX');
  try {
    const since = new Date(Date.now() - 5 * 60_000);
    const searchDate = new Date(since);
    searchDate.setHours(0, 0, 0, 0);

    const uids = await client.search({ since: searchDate }, { uid: true });
    if (!uids?.length) return;

    for await (const msg of client.fetch(uids,
      { envelope: true, bodyParts: ['TEXT', 'HTML', '1', '2'], uid: true },
      { uid: true }
    )) {
      const received = msg.envelope?.date ? new Date(msg.envelope.date) : new Date();
      if (received < since) continue;
      processMsg(mailbox, {
        uid: String(msg.uid),
        received,
        subject: msg.envelope?.subject || '',
        from: String(msg.envelope?.from?.[0]?.address || '').toLowerCase(),
        body: extractText(msg).slice(0, 20000)
      });
    }

    db.prepare('UPDATE mailboxes SET last_sync = ? WHERE id = ?')
      .run(Math.floor(Date.now() / 1000), mailbox.id);
  } finally {
    lock.release();
  }
}

// ── حلقة IDLE — تستقبل إشعارات فورية من السيرفر ─────────────────────────
async function idleLoop(client, mailbox) {
  const entry = liveConns.get(mailbox.id);

  while (entry && liveConns.has(mailbox.id)) {
    try {
      // waitForExist ينتظر رسائل جديدة — يرجع فور ما يوصل شيء
      const updated = await client.idle();

      if (!updated || !liveConns.has(mailbox.id)) break;

      // وصل إشعار — نجلب الرسائل الجديدة فقط
      const lock = await client.getMailboxLock('INBOX');
      try {
        const lastSync = mailbox.last_sync
          ? new Date(mailbox.last_sync * 1000)
          : new Date(Date.now() - 5 * 60_000);
        const since = new Date(lastSync.getTime() - 30_000); // 30 ثانية هامش

        const searchDate = new Date(since);
        searchDate.setHours(0, 0, 0, 0);

        const uids = await client.search({ since: searchDate }, { uid: true });

        if (uids?.length) {
          for await (const msg of client.fetch(uids,
            { envelope: true, bodyParts: ['TEXT', 'HTML', '1', '2'], uid: true },
            { uid: true }
          )) {
            const received = msg.envelope?.date ? new Date(msg.envelope.date) : new Date();
            if (received < since) continue;
            processMsg(mailbox, {
              uid: String(msg.uid),
              received,
              subject: msg.envelope?.subject || '',
              from: String(msg.envelope?.from?.[0]?.address || '').toLowerCase(),
              body: extractText(msg).slice(0, 20000)
            });
          }
        }

        // تحديث last_sync وإعادة قراءة الصف
        const now = Math.floor(Date.now() / 1000);
        db.prepare('UPDATE mailboxes SET last_sync = ?, status = ?, last_error = NULL WHERE id = ?')
          .run(now, 'connected', mailbox.id);
        mailbox.last_sync = now;

      } finally {
        lock.release();
      }

    } catch (err) {
      if (liveConns.has(mailbox.id)) {
        console.error(`[IMAP] IDLE انقطع ${mailbox.email}:`, err.message);
        db.prepare("UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?")
          .run(String(err.message).slice(0, 200), mailbox.id);
        liveConns.delete(mailbox.id);
        const delay = getRetryDelay(mailbox.id);
        console.log(`[IMAP] 🔄 إعادة الاتصال ${mailbox.email} بعد ${delay/1000}ث`);
        setTimeout(() => connectMailbox(mailbox), delay);
      }
      break;
    }
  }
}

// ── مزامنة قائمة الصناديق كل 30 ثانية (ربط جديد / حذف) ──────────────────
async function syncMailboxList() {
  const mailboxes = db.prepare(
    "SELECT * FROM mailboxes WHERE status != 'disconnected'"
  ).all();

  // اتصل بالصناديق الجديدة
  for (const mb of mailboxes) {
    if (!liveConns.has(mb.id)) {
      connectMailbox(mb);
    }
  }

  // اقطع صناديق اشتُلت أو disconnected
  const activeIds = new Set(mailboxes.map(m => m.id));
  for (const [id, entry] of liveConns) {
    if (!activeIds.has(id)) {
      try { await entry.client.logout().catch(() => {}); } catch {}
      liveConns.delete(id);
      console.log(`[IMAP] 🔌 قطع اتصال صندوق محذوف ${id}`);
    }
  }

  // تنظيف الأكواد المنتهية
  db.prepare('DELETE FROM codes WHERE expires_at < ?')
    .run(Math.floor(Date.now() / 1000) - 3600);
}

// ── pollAll — تُستدعى من server.js (للتوافق) ─────────────────────────────
let syncStarted = false;
export async function pollAll() {
  if (!syncStarted) {
    syncStarted = true;
    await syncMailboxList();
    setInterval(syncMailboxList, 30_000); // تحقق من صناديق جديدة كل 30 ث
  }
}
