// IMAP removed — system now uses webhook forwarding
// Stubs kept so any stale import doesn't crash on startup

export function guessHost(_email) {
  return '';
}

export async function testConnection(_email, _pass, _host, _port) {
  throw new Error('IMAP disabled — use webhook forwarding');
}

export async function fetchMessages(_email, _pass, _host, _port, _since) {
  return [];
}
