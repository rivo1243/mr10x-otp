import Database from 'better-sqlite3';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';
import { randomUUID } from 'node:crypto';

const __dirname = dirname(fileURLToPath(import.meta.url));
const DATA_DIR = join(__dirname, '../../data');
mkdirSync(DATA_DIR, { recursive: true });

const db = new Database(join(DATA_DIR, 'mr10x.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS sellers (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    email       TEXT UNIQUE NOT NULL,
    password    TEXT NOT NULL,
    phone       TEXT DEFAULT '',
    status      TEXT DEFAULT 'pending',
    created_at  INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS mailboxes (
    id          TEXT PRIMARY KEY,
    seller_id   TEXT NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
    email       TEXT NOT NULL,
    imap_host   TEXT NOT NULL,
    imap_port   INTEGER DEFAULT 993,
    password    TEXT NOT NULL,
    label       TEXT DEFAULT '',
    status      TEXT DEFAULT 'connected',
    last_sync   INTEGER,
    last_error  TEXT,
    created_at  INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS slots (
    id               TEXT PRIMARY KEY,
    seller_id        TEXT NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
    mailbox_id       TEXT NOT NULL REFERENCES mailboxes(id) ON DELETE CASCADE,
    label            TEXT NOT NULL,
    token            TEXT UNIQUE NOT NULL,
    account_email    TEXT DEFAULT '',
    account_password TEXT DEFAULT '',
    created_at       INTEGER DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS codes (
    id          TEXT PRIMARY KEY,
    slot_id     TEXT NOT NULL REFERENCES slots(id) ON DELETE CASCADE,
    code        TEXT NOT NULL,
    email_from  TEXT,
    email_subj  TEXT,
    received_at INTEGER NOT NULL,
    expires_at  INTEGER NOT NULL,
    viewed      INTEGER DEFAULT 0
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS email_verifications (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    code       TEXT NOT NULL,
    name       TEXT NOT NULL,
    password   TEXT NOT NULL,
    phone      TEXT DEFAULT '',
    expires_at INTEGER NOT NULL,
    used       INTEGER DEFAULT 0
  );
`);

db.exec(`
  CREATE TABLE IF NOT EXISTS password_resets (
    id         TEXT PRIMARY KEY,
    email      TEXT NOT NULL,
    token      TEXT UNIQUE NOT NULL,
    expires_at INTEGER NOT NULL,
    used       INTEGER DEFAULT 0
  );
`);

// ── Migrations ────────────────────────────────────────────────────────────────
try { db.exec(`ALTER TABLE slots ADD COLUMN account_email TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE slots ADD COLUMN account_password TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE sellers ADD COLUMN phone TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE sellers ADD COLUMN status TEXT DEFAULT 'pending'`); } catch {}
try { db.exec(`ALTER TABLE slots ADD COLUMN code_attempts INTEGER DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE sellers ADD COLUMN subscription_expires_at INTEGER DEFAULT NULL`); } catch {}
// plan_type: 'plan1' = 1 slot فقط | 'plan2' = غير محدود | 'plan3' = كل الميزات (غير محدود)
try { db.exec(`ALTER TABLE sellers ADD COLUMN plan_type TEXT DEFAULT 'plan2'`); } catch {}
try { db.exec(`ALTER TABLE email_verifications ADD COLUMN plan_type TEXT DEFAULT 'plan2'`); } catch {}

// F-03: separate api_token column so the seller's UUID is not used as auth token
try { db.exec(`ALTER TABLE sellers ADD COLUMN api_token TEXT`); } catch {}
try { db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_sellers_api_token ON sellers(api_token)`); } catch {}

// Populate api_token for existing sellers that have none
const sellersWithoutToken = db.prepare("SELECT id FROM sellers WHERE api_token IS NULL").all();
const fillToken = db.prepare("UPDATE sellers SET api_token = ? WHERE id = ?");
for (const s of sellersWithoutToken) {
  fillToken.run(randomUUID(), s.id);
}

// F-05: per-user salt for password hashing
try { db.exec(`ALTER TABLE sellers ADD COLUMN salt TEXT DEFAULT NULL`); } catch {}

// F-04: flag whether mailbox password is encrypted
try { db.exec(`ALTER TABLE mailboxes ADD COLUMN password_encrypted INTEGER DEFAULT 0`); } catch {}

// N-01: flag whether slot account_password is encrypted
try { db.exec(`ALTER TABLE slots ADD COLUMN account_password_encrypted INTEGER DEFAULT 0`); } catch {}

// F-09: indexes for high-frequency lookups
try { db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_slots_token ON slots(token)`); } catch {}
try { db.exec(`CREATE INDEX IF NOT EXISTS idx_codes_slot_id ON codes(slot_id)`); } catch {}

// Webhook forwarding — each mailbox gets a unique inbound token
try { db.exec(`ALTER TABLE mailboxes ADD COLUMN webhook_token TEXT`); } catch {}
try { db.exec(`CREATE UNIQUE INDEX IF NOT EXISTS idx_mailboxes_webhook_token ON mailboxes(webhook_token)`); } catch {}

// Populate webhook_token for existing mailboxes that have none
const mailboxesWithoutToken = db.prepare("SELECT id FROM mailboxes WHERE webhook_token IS NULL").all();
const fillWebhookToken = db.prepare("UPDATE mailboxes SET webhook_token = ? WHERE id = ?");
for (const m of mailboxesWithoutToken) {
  fillWebhookToken.run(randomUUID(), m.id);
}

// F-11: clean up stale verification and reset records (older than 24h past expiry)
db.prepare('DELETE FROM email_verifications WHERE expires_at < unixepoch() - 86400').run();
db.prepare('DELETE FROM password_resets WHERE expires_at < unixepoch() - 86400').run();

export default db;
