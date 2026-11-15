import Database from 'better-sqlite3';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mkdirSync } from 'node:fs';

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

// Migrations: إضافة حقول جديدة للجداول القديمة
try { db.exec(`ALTER TABLE slots ADD COLUMN account_email TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE slots ADD COLUMN account_password TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE sellers ADD COLUMN phone TEXT DEFAULT ''`); } catch {}
try { db.exec(`ALTER TABLE sellers ADD COLUMN status TEXT DEFAULT 'pending'`); } catch {}
try { db.exec(`ALTER TABLE slots ADD COLUMN code_attempts INTEGER DEFAULT 0`); } catch {}
try { db.exec(`ALTER TABLE sellers ADD COLUMN subscription_expires_at INTEGER DEFAULT NULL`); } catch {}

export default db;
