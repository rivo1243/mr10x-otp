import db from './db.js';
import { fetchMessages } from './imap.js';
import { extractCode } from './extract.js';
import { randomUUID } from 'node:crypto';

let running = false;

async function pollMailbox(mailbox) {
  const since = mailbox.last_sync
    ? new Date(mailbox.last_sync * 1000)
    : new Date(Date.now() - 24 * 60 * 60 * 1000); // آخر 24 ساعة عند أول مزامنة

  try {
    for await (const msg of fetchMessages(
      mailbox.email, mailbox.password,
      mailbox.imap_host, mailbox.imap_port, since
    )) {
      const code = extractCode(msg.subject, msg.body);
      if (!code) continue;

      // إيجاد الـ slots المرتبطة بهذا الصندوق
      const slots = db.prepare(
        `SELECT * FROM slots WHERE mailbox_id = ? AND seller_id = ?`
      ).all(mailbox.id, mailbox.seller_id);

      for (const slot of slots) {
        // تجنب التكرار
        const exists = db.prepare(
          `SELECT id FROM codes WHERE slot_id = ? AND code = ? AND received_at = ?`
        ).get(slot.id, code, Math.floor(msg.received.getTime() / 1000));
        if (exists) continue;

        db.prepare(`
          INSERT INTO codes (id, slot_id, code, email_from, email_subj, received_at, expires_at)
          VALUES (?, ?, ?, ?, ?, ?, ?)
        `).run(
          randomUUID(), slot.id, code,
          msg.from, msg.subject.slice(0, 200),
          Math.floor(msg.received.getTime() / 1000),
          Math.floor(Date.now() / 1000) + 10 * 60 // ينتهي بعد 10 دقائق
        );
      }
    }

    db.prepare(`UPDATE mailboxes SET last_sync = ?, last_error = NULL, status = 'connected' WHERE id = ?`)
      .run(Math.floor(Date.now() / 1000), mailbox.id);

  } catch (err) {
    db.prepare(`UPDATE mailboxes SET last_error = ?, status = 'error' WHERE id = ?`)
      .run(String(err.message).slice(0, 200), mailbox.id);
  }
}

export async function pollAll() {
  if (running) return;
  running = true;
  try {
    const mailboxes = db.prepare(`SELECT * FROM mailboxes WHERE status != 'disconnected'`).all();
    for (const mb of mailboxes) {
      await pollMailbox(mb);
    }
    // تنظيف الأكواد المنتهية
    db.prepare(`DELETE FROM codes WHERE expires_at < ?`).run(Math.floor(Date.now() / 1000) - 3600);
  } catch (e) {
    console.error('Poll cycle error:', e.message);
  } finally {
    running = false;
  }
}
