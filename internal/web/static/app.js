import { state, isAdmin, on } from './state.js';
import { api, onUnauthorized } from './api.js';
import { $, $$, closeModal } from './ui.js';
import { initCerts, loadCertificates, renderQuickZones } from './certs.js';
import { initDNS, loadDNSZones } from './dns.js';
import { initAccounts, loadAccounts } from './accounts.js';
import { initSystem, activateSystemView } from './system.js';
import { initJobs, loadJobs } from './jobs.js';

const TABS = ['certs', 'dns', 'accounts', 'jobs', 'system'];

const VIEW_META = {
  certs: {
    title: 'TLS 证书管理',
    desc: '管理 ACME 自动签发与外部导入证书，支持多格式证书包下载、在线复制 PEM 与到期自动续期。',
  },
  dns: {
    title: 'DNS 解析管理',
    desc: '统一管理多个阿里云中国站与国际站主域名解析记录，支持新域名接入、模糊检索与标准 BIND Zone 导出。',
  },
  accounts: {
    title: '阿里云账户',
    desc: '配置多个阿里云中国站、国际站或自定义接入点账户，AccessKey Secret 采用 AES-256-GCM 静态加密存储。',
  },
  jobs: {
    title: '任务队列',
    desc: '跟踪 ACME 证书签发与自动续期后台调度队列，支持实时查看 DNS-01 验证与签发日志输出。',
  },
  system: {
    title: '系统与安全',
    descAdmin: '管理系统用户角色权限、边缘节点 Pull API 最小权限令牌、安全操作审计日志与 Webhook 告警通知。',
    descUser: '管理当前登录账号密码与个人安全配置。',
  },
};

function roleLabel(role) {
  if (role === 'admin') return '系统管理员 · admin';
  if (role === 'operator') return '运维操作员 · operator';
  return '只读审计员 · viewer';
}

function updateSidebarAndBadges() {
  const userNameEl = $('#sidebar-user-name');
  const userRoleEl = $('#sidebar-user-role');
  const hostBadge = $('#host-badge');

  if (userNameEl) {
    userNameEl.textContent = state.user
      ? state.user.display_name || state.user.username
      : '—';
  }
  if (userRoleEl) {
    userRoleEl.textContent = state.user ? roleLabel(state.user.role) : '—';
  }
  if (hostBadge) {
    hostBadge.textContent = state.hostname ? `入口: ${state.hostname}` : '';
  }

  const certBadge = $('#nav-cert-badge');
  if (certBadge) certBadge.textContent = String(state.certs.length);

  const acctBadge = $('#nav-acct-badge');
  if (acctBadge) acctBadge.textContent = String(state.accounts.length);

  const activeJobs = state.jobs.filter(
    (j) => j.status === 'queued' || j.status === 'running',
  ).length;
  const jobBadge = $('#nav-job-badge');
  if (jobBadge) {
    jobBadge.textContent = String(activeJobs);
    jobBadge.hidden = activeJobs === 0;
  }
}

function applyTabHeader(tab) {
  const meta = VIEW_META[tab] || VIEW_META.certs;
  const titleEl = $('#view-title');
  const descEl = $('#view-desc');
  if (titleEl) titleEl.textContent = meta.title;
  if (descEl) {
    descEl.textContent =
      tab === 'system' ? (isAdmin() ? meta.descAdmin : meta.descUser) : meta.desc;
  }
}

function setActiveTabDOM(tab) {
  $$('.nav-item[data-tab]').forEach((btn) => {
    btn.classList.toggle('active', btn.dataset.tab === tab);
  });
  for (const name of TABS) {
    const pane = $(`#tab-${name}`);
    if (pane) pane.hidden = name !== tab;
  }
  applyTabHeader(tab);
}

function switchTab(tab, { skipFetch = false } = {}) {
  const next = TABS.includes(tab) ? tab : 'certs';
  state.activeTab = next;
  setActiveTabDOM(next);

  if (skipFetch) return;

  if (next === 'certs') {
    loadCertificates();
  } else if (next === 'dns') {
    loadDNSZones(false);
  } else if (next === 'accounts') {
    loadAccounts();
  } else if (next === 'jobs') {
    loadJobs();
  } else if (next === 'system') {
    activateSystemView();
  }
}

function showLogin() {
  closeModal();
  clearInterval(state.pollTimer);
  state.pollTimer = null;
  state.csrf = '';
  state.user = null;

  const boot = $('#boot');
  const appView = $('#app-view');
  const loginView = $('#login-view');
  const errBox = $('#login-error');
  const pwInput = $('#login-password');

  if (boot) boot.hidden = true;
  if (appView) appView.hidden = true;
  if (loginView) loginView.hidden = false;
  if (errBox) errBox.hidden = true;
  if (pwInput) {
    pwInput.value = '';
    pwInput.focus();
  }
}

async function showApp() {
  const boot = $('#boot');
  const loginView = $('#login-view');
  const appView = $('#app-view');

  if (boot) boot.hidden = true;
  if (loginView) loginView.hidden = true;
  if (appView) appView.hidden = false;

  state.activeSysTab = isAdmin() ? 'users' : 'profile';
  const initialTab = TABS.includes(state.activeTab) ? state.activeTab : 'certs';
  switchTab(initialTab, { skipFetch: true });
  updateSidebarAndBadges();

  await Promise.all([loadAccounts(), loadCertificates(), loadJobs()]);
  renderQuickZones();
  updateSidebarAndBadges();

  if (initialTab === 'dns') {
    await loadDNSZones(false);
  } else if (initialTab === 'system') {
    activateSystemView();
  }

  clearInterval(state.pollTimer);
  state.pollTimer = setInterval(() => {
    if (!state.user) return;
    const hasActive =
      state.jobs.some((j) => j.status === 'queued' || j.status === 'running') ||
      state.certs.some(
        (c) =>
          c.active_job ||
          c.status === 'queued' ||
          c.status === 'issuing' ||
          c.status === 'renewing',
      );
    if (hasActive) {
      loadCertificates();
      loadJobs();
    }
  }, 3000);
}

function bindGlobalEvents() {
  onUnauthorized(showLogin);

  on('nav:switch', (tab) => {
    if (tab) switchTab(tab);
  });

  on('certs:changed', async (detail) => {
    if (!detail || !detail.loaded) {
      await loadCertificates();
    }
    updateSidebarAndBadges();
    loadJobs();
  });

  on('accounts:changed', () => {
    updateSidebarAndBadges();
  });

  $$('.nav-item[data-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      switchTab(btn.dataset.tab);
    });
  });

  $('#login-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const errBox = $('#login-error');
    if (errBox) errBox.hidden = true;
    try {
      const res = await api('/api/login', {
        method: 'POST',
        body: {
          username: ($('#login-username')?.value || '').trim(),
          password: $('#login-password')?.value || '',
        },
      });
      state.csrf = res.csrf || '';
      state.user = res.user || null;
      state.hostname = res.hostname || state.hostname || '';
      if (!state.hostname || !state.user) {
        const sess = await api('/api/session');
        state.hostname = sess.hostname || state.hostname || '';
        state.user = sess.user || state.user;
        if (sess.csrf) state.csrf = sess.csrf;
      }
      state.activeTab = 'certs';
      await showApp();
    } catch (err) {
      if (errBox) {
        errBox.textContent = err.message;
        errBox.hidden = false;
      }
    }
  });

  $('#logout-btn')?.addEventListener('click', async () => {
    try {
      await api('/api/logout', { method: 'POST', body: {} });
    } catch (_) {}
    showLogin();
  });
}

async function boot() {
  initCerts();
  initDNS();
  initAccounts();
  initSystem();
  initJobs();
  bindGlobalEvents();

  try {
    const sess = await api('/api/session');
    state.hostname = sess.hostname || '';
    if (sess.authenticated) {
      state.csrf = sess.csrf || '';
      state.user = sess.user || null;
      await showApp();
    } else {
      showLogin();
    }
  } catch (_) {
    showLogin();
  }
}

boot();
