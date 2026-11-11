export const state = {
  csrf: '',
  hostname: '',
  user: null,
  certs: [],
  jobs: [],
  accounts: [],
  zoneItems: [],
  currentAccountFilter: '',
  currentZone: '',
  currentZoneAccount: '',
  dnsPage: 1,
  dnsRecords: [],
  dnsTotal: 0,
  users: [],
  tokens: [],
  auditLogs: [],
  pollTimer: null,
  activeTab: 'certs',
  activeSysTab: 'users',
};

export function isAdmin() {
  return Boolean(state.user && state.user.role === 'admin');
}

export function isViewer() {
  return Boolean(state.user && state.user.role === 'viewer');
}

const listeners = new Map();

export function on(event, fn) {
  if (typeof fn !== 'function') return () => {};
  let handlers = listeners.get(event);
  if (!handlers) {
    handlers = new Set();
    listeners.set(event, handlers);
  }
  handlers.add(fn);
  return () => {
    handlers.delete(fn);
  };
}

export function emit(event, detail) {
  const handlers = listeners.get(event);
  if (!handlers) return;
  for (const fn of [...handlers]) {
    fn(detail);
  }
}
