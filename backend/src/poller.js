// IMAP poller removed — system now uses webhook forwarding
// Stubs kept so any stale import doesn't crash on startup

export async function pollAll() {
  // no-op: webhook approach needs no polling
}

export async function disconnectMailbox(_id) {
  // no-op
}
