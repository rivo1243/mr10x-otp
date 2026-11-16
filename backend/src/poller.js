import db from './db.js';
import { ImapFlow } from 'imapflow';
import { convert } from 'html-to-text';
import { extractCode } from './extract.js';
import { randomUUID } from 'node:crypto';

// ── خريطة connections الحية: mailbox_id → { client, busy }
const liveConns = new Map();

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
async function processMsg(mailbox, msg) {
  const code = extractCode(msg.subject, msg.body);
  if (!code) return;

  const slots = await db.prepare(
    'SELECT * FROM slots WHERE mailbox_id = ? AND seller_id = ?'
  ).all(mailbox.id, mailbox.seller_id);

  const receivedTs = Math.floor(msg.received.getTime() / 1000);

  for (const slot of slots) {
    const exists = await db.prepare(
      'SELECT id FROM codes WHERE slot_id = ? AND code = ? AND received_at = ?'
    ).get(slot.id, code, receivedTs);
    if (exists) continue;

    await db.prepare(`
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
    auth: { user: mailbox.email, pass: mailbox.password },
    logger: false,
    tls: { rejectUnauthorized: false }
  });

  liveConns.set(mailbox.id, { client, busy: false });

  client.on('error', (err) => {
    console.error(`[IMAP] خطأ ${mailbox.email}:`, err.message);
    // fire-and-forget — event handlers can't be async
    db.prepare("UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?")
      .run(String(err.message).slice(0, 200), mailbox.id).catch(() => {});
    liveConns.delete(mailbox.id);
    // إعادة المحاولة بعد 15 ثانية
    setTimeout(() => connectMailbox(mailbox), 15_000);
  });

  try {
    await client.connect();

    // جلب الرسائل اللي وصلت في آخر 5 دقائق عند الاتصال الأول
    await initialFetch(client, mailbox);

    await db.prepare("UPDATE mailboxes SET status = 'connected', last_error = NULL WHERE id = ?")
      .run(mailbox.id);

    console.log(`[IMAP] ✅ متصل ${mailbox.email} — IDLE فعّال`);

    // ابدأ حلقة IDLE — تنتظر إشعار من السيرفر
    idleLoop(client, mailbox);

  } catch (err) {
    console.error(`[IMAP] فشل الاتصال ${mailbox.email}:`, err.message);
    await db.prepare("UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?")
      .run(String(err.message).slice(0, 200), mailbox.id);
    liveConns.delete(mailbox.id);
    setTimeout(() => connectMailbox(mailbox), 30_000);
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
      await processMsg(mailbox, {
        uid: String(msg.uid),
        received,
        subject: msg.envelope?.subject || '',
        from: String(msg.envelope?.from?.[0]?.address || '').toLowerCase(),
        body: extractText(msg).slice(0, 20000)
      });
    }

    await db.prepare('UPDATE mailboxes SET last_sync = ? WHERE id = ?')
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
            await processMsg(mailbox, {
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
        await db.prepare('UPDATE mailboxes SET last_sync = ?, status = ?, last_error = NULL WHERE id = ?')
          .run(now, 'connected', mailbox.id);
        mailbox.last_sync = now;

      } finally {
        lock.release();
      }

    } catch (err) {
      if (liveConns.has(mailbox.id)) {
        console.error(`[IMAP] IDLE انقطع ${mailbox.email}:`, err.message);
        await db.prepare("UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?")
          .run(String(err.message).slice(0, 200), mailbox.id);
        liveConns.delete(mailbox.id);
        setTimeout(() => connectMailbox(mailbox), 10_000);
      }
      break;
    }
  }
}

// ── مزامنة قائمة الصناديق كل 30 ثانية (ربط جديد / حذف) ──────────────────
async function syncMailboxList() {
  const mailboxes = await db.prepare(
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
  await db.prepare('DELETE FROM codes WHERE expires_at < ?')
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
