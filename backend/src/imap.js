import { ImapFlow } from 'imapflow';
import { convert } from 'html-to-text';

export function guessHost(email) {
  const domain = String(email).split('@')[1]?.toLowerCase() || '';
  const map = {
    'gmail.com': 'imap.gmail.com',
    'googlemail.com': 'imap.gmail.com',
    'yahoo.com': 'imap.mail.yahoo.com',
    'hotmail.com': 'outlook.office365.com',
    'outlook.com': 'outlook.office365.com',
    'live.com': 'outlook.office365.com',
    'icloud.com': 'imap.mail.me.com',
    'me.com': 'imap.mail.me.com',
    'aol.com': 'imap.aol.com',
    'zoho.com': 'imap.zoho.com',
  };
  return map[domain] || `mail.${domain}`;
}

export async function testConnection(email, password, host, port = 993) {
  const client = new ImapFlow({
    host, port, secure: true,
    auth: { user: email, pass: password },
    logger: false,
    tls: { rejectUnauthorized: false }
  });
  try {
    await client.connect();
    await client.logout();
    return true;
  } catch (e) {
    const msg = String(e.message || '').toLowerCase();
    const isGmail = host.includes('gmail');
    const isOutlook = host.includes('outlook') || host.includes('office365');
    const isYahoo = host.includes('yahoo');

    // كشف أخطاء المصادقة
    if (
      msg.includes('invalid credentials') ||
      msg.includes('authentication failed') ||
      msg.includes('authenticate') ||
      msg.includes('login failed') ||
      msg.includes('username and password') ||
      msg.includes('[authenticationfailed]') ||
      msg.includes('command failed') ||
      msg.includes('no supported')
    ) {
      if (isGmail) {
        throw new Error(
          'AUTH_FAIL:GMAIL'
        );
      }
      if (isOutlook) {
        throw new Error(
          'AUTH_FAIL:OUTLOOK'
        );
      }
      if (isYahoo) {
        throw new Error(
          'AUTH_FAIL:YAHOO'
        );
      }
      throw new Error('AUTH_FAIL:GENERIC');
    }

    // أخطاء الاتصال
    if (
      msg.includes('econnrefused') ||
      msg.includes('enotfound') ||
      msg.includes('etimedout') ||
      msg.includes('timeout') ||
      msg.includes('network')
    ) {
      throw new Error('CONN_FAIL');
    }

    throw e;
  }
}

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

export async function* fetchMessages(email, password, host, port, since) {
  const client = new ImapFlow({
    host, port: Number(port) || 993, secure: true,
    auth: { user: email, pass: password },
    logger: false,
    tls: { rejectUnauthorized: false }
  });

  await client.connect();
  try {
    const lock = await client.getMailboxLock('INBOX');
    try {
      const sinceDate = new Date(since.getTime() - 5 * 60_000);
      const searchDate = new Date(sinceDate);
      searchDate.setHours(0, 0, 0, 0);

      const uids = await client.search({ since: searchDate }, { uid: true });
      if (!uids?.length) return;

      for await (const msg of client.fetch(uids,
        { envelope: true, bodyParts: ['TEXT', 'HTML', '1', '2'], uid: true },
        { uid: true }
      )) {
        const received = msg.envelope?.date ? new Date(msg.envelope.date) : new Date();
        if (received < sinceDate) continue;
        yield {
          uid: String(msg.uid),
          received,
          subject: msg.envelope?.subject || '',
          from: String(msg.envelope?.from?.[0]?.address || '').toLowerCase(),
          body: extractText(msg).slice(0, 20000)
        };
      }
    } finally { lock.release(); }
  } finally { await client.logout().catch(() => {}); }
}
