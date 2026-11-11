import { state, isAdmin, on, emit } from './state.js';
import { api } from './api.js';
import { $, $$, el, notify, copyText, fmtTime, roleBadge } from './ui.js';

const SYS_TABS = ['users', 'tokens', 'audit', 'profile'];

function syncWebhookTestBtn() {
  const input = $('#webhook-url');
  const testBtn = $('#test-webhook-btn');
  if (!input || !testBtn) return;
  testBtn.disabled = input.value.trim() === '';
}

async function loadSettings() {
  if (!isAdmin()) return;
  try {
    const s = await api('/api/settings');
    const input = $('#webhook-url');
    if (input) input.value = s.webhook_url || '';
    syncWebhookTestBtn();
  } catch (_) {}
}

async function loadUsers() {
  if (!isAdmin()) return;
  try {
    const data = await api('/api/users');
    state.users = data.users || [];
    renderUsers();
  } catch (err) {
    notify(err.message, true);
  }
}

function renderUsers() {
  const tbody = $('#users-tbody');
  if (!tbody) return;
  tbody.replaceChildren();

  if (state.users.length === 0) {
    tbody.append(el('tr', {}, el('td', { colspan: 5, class: 'empty-cell' }, '暂无系统用户')));
    return;
  }

  for (const u of state.users) {
    const isMe = Boolean(state.user && state.user.id === u.id);

    const editBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-secondary btn-sm',
        onclick: () => openUserEditor(u),
      },
      '编辑 / 改密',
    );

    const delBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-danger btn-sm',
        disabled: isMe,
        onclick: async () => {
          if (!confirm(`确定删除用户 [${u.username}] 吗？`)) return;
          try {
            await api(`/api/users/${u.id}`, { method: 'DELETE' });
            if ($('#user-edit-id')?.value === u.id) {
              $('#user-form').hidden = true;
            }
            notify('用户已删除');
            await loadUsers();
            emit('audit:changed');
          } catch (err) {
            notify(err.message, true);
          }
        },
      },
      '删除',
    );

    tbody.append(
      el(
        'tr',
        {},
        el(
          'td',
          {},
          el('strong', {}, u.username),
          isMe ? el('span', { class: 'badge badge-info badge-ml' }, '当前登录') : null,
          el('div', { class: 'muted small' }, u.display_name || '—'),
        ),
        el('td', {}, roleBadge(u.role)),
        el(
          'td',
          {},
          el(
            'span',
            { class: u.enabled ? 'badge badge-success' : 'badge badge-danger' },
            u.enabled ? '正常' : '已禁用',
          ),
        ),
        el(
          'td',
          {},
          el('div', {}, fmtTime(u.last_login_at)),
          u.last_login_ip ? el('div', { class: 'muted small' }, `IP: ${u.last_login_ip}`) : null,
        ),
        el(
          'td',
          { class: 'text-right' },
          el('div', { class: 'btn-row-end' }, editBtn, delBtn),
        ),
      ),
    );
  }
}

function openUserEditor(u = null) {
  const form = $('#user-form');
  if (!form) return;
  form.hidden = false;

  const isMe = Boolean(u && state.user && state.user.id === u.id);

  $('#user-form-title').textContent = u ? `编辑用户 · ${u.username}` : '新增系统用户';
  $('#user-edit-id').value = u ? u.id : '';
  $('#user-username').value = u ? u.username : '';
  $('#user-username').disabled = Boolean(u);
  $('#user-display').value = u ? u.display_name || '' : '';
  $('#user-role').value = u ? u.role : 'operator';
  $('#user-role').disabled = isMe;
  $('#user-password').value = '';
  $('#user-password').required = !u;
  $('#user-pw-hint').textContent = u ? '(留空不修改)' : '(至少10位)';
  $('#user-enabled').checked = u ? Boolean(u.enabled) : true;
  $('#user-enabled').disabled = isMe;

  (u ? $('#user-display') : $('#user-username'))?.focus();
}

function pickSampleDomain(domains) {
  const list = Array.isArray(domains) ? domains : [];
  const exact = list.find((d) => d && d !== '*' && !d.startsWith('*.'));
  if (exact) return exact;
  const wildcard = list.find((d) => d && d.startsWith('*.'));
  if (wildcard) return wildcard.replace(/^\*\./, 'www.');
  return state.hostname || 'example.com';
}

function renderTokenCreatedBanner(tokenObj, plaintext) {
  const banner = $('#token-created-banner');
  if (!banner) return;

  const origin = window.location.origin;
  const sampleDomain = pickSampleDomain(tokenObj?.allowed_domains);
  const baseUrl = `${origin}/api/v1/pull/certificates/${sampleDomain}`;

  const cmdJson = `curl -fsSL -H "Authorization: Bearer ${plaintext}" "${baseUrl}"`;
  const cmdFullchain = `curl -fsSL -H "Authorization: Bearer ${plaintext}" "${baseUrl}?file=fullchain"`;
  const cmdPrivkey = `curl -fsSL -H "Authorization: Bearer ${plaintext}" "${baseUrl}?file=privkey"`;

  banner.replaceChildren(
    el(
      'div',
      {},
      el(
        'strong',
        { class: 'text-green' },
        `✓ 令牌 [${tokenObj?.name || 'API Token'}] 已生成（仅显示一次，请立即复制保存）：`,
      ),
    ),
    el(
      'div',
      { class: 'btn-row' },
      el('code', { class: 'token-banner-code' }, plaintext),
      el(
        'button',
        {
          type: 'button',
          class: 'btn btn-secondary btn-sm',
          onclick: () => copyText(plaintext, 'API Token'),
        },
        '复制 Token',
      ),
    ),
    el(
      'div',
      { class: 'cmd-list' },
      el(
        'div',
        { class: 'cmd-row' },
        el('code', {}, cmdJson),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-secondary btn-sm',
            onclick: () => copyText(cmdJson, 'JSON 元数据拉取命令'),
          },
          '复制 JSON 拉取命令',
        ),
      ),
      el(
        'div',
        { class: 'cmd-row' },
        el('code', {}, cmdFullchain),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-secondary btn-sm',
            onclick: () => copyText(cmdFullchain, '证书链拉取命令'),
          },
          '复制 fullchain 命令',
        ),
      ),
      el(
        'div',
        { class: 'cmd-row' },
        el('code', {}, cmdPrivkey),
        el(
          'button',
          {
            type: 'button',
            class: 'btn btn-secondary btn-sm',
            onclick: () => copyText(cmdPrivkey, '私钥拉取命令'),
          },
          '复制 privkey 命令',
        ),
      ),
    ),
  );
  banner.hidden = false;
}

function openTokenEditor(t = null) {
  const form = $('#token-form');
  if (!form) return;
  form.hidden = false;

  if (!t) {
    const banner = $('#token-created-banner');
    if (banner) banner.hidden = true;
  }

  $('#token-edit-id').value = t ? t.id : '';
  $('#token-form-title').textContent = t
    ? `编辑 API 令牌 · ${t.name}`
    : '新增证书拉取 API 令牌';
  $('#token-submit-btn').textContent = t ? '保存修改' : '生成令牌';
  $('#token-name').value = t ? t.name || '' : '';
  $('#token-domains').value = t
    ? (t.allowed_domains && t.allowed_domains.length > 0 ? t.allowed_domains : ['*']).join(', ')
    : 'example.com, *.example.com';
  $('#token-name')?.focus();
}

async function loadTokens() {
  if (!isAdmin()) return;
  try {
    const data = await api('/api/tokens');
    state.tokens = data.tokens || [];
    renderTokens();
  } catch (err) {
    notify(err.message, true);
  }
}

function renderTokens() {
  const tbody = $('#tokens-tbody');
  if (!tbody) return;
  tbody.replaceChildren();

  if (!state.tokens || state.tokens.length === 0) {
    tbody.append(
      el('tr', {}, el('td', { colspan: 5, class: 'empty-cell' }, '尚未创建证书拉取 API 令牌')),
    );
    return;
  }

  for (const t of state.tokens) {
    const editBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-secondary btn-sm',
        onclick: () => openTokenEditor(t),
      },
      '编辑',
    );

    const toggleBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-secondary btn-sm',
        onclick: async () => {
          try {
            await api(`/api/tokens/${t.id}`, {
              method: 'PUT',
              body: { enabled: !t.enabled },
            });
            notify(t.enabled ? '令牌已禁用' : '令牌已启用');
            await loadTokens();
            emit('audit:changed');
          } catch (err) {
            notify(err.message, true);
          }
        },
      },
      t.enabled ? '禁用' : '启用',
    );

    const delBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-danger btn-sm',
        onclick: async () => {
          if (!confirm(`确定删除 API 令牌 [${t.name}] 吗？远程节点将无法继续拉取证书。`)) return;
          try {
            await api(`/api/tokens/${t.id}`, { method: 'DELETE' });
            if ($('#token-edit-id')?.value === t.id) {
              $('#token-form').hidden = true;
              $('#token-edit-id').value = '';
            }
            notify('API 令牌已删除');
            await loadTokens();
            emit('audit:changed');
          } catch (err) {
            notify(err.message, true);
          }
        },
      },
      '删除',
    );

    const domainBadges = el('div', { class: 'btn-row' });
    for (const d of t.allowed_domains || ['*']) {
      domainBadges.append(el('span', { class: 'badge badge-blue' }, d));
    }

    tbody.append(
      el(
        'tr',
        {},
        el(
          'td',
          {},
          el('strong', {}, t.name),
          el('div', { class: 'muted small' }, el('code', {}, t.token_prefix)),
        ),
        el('td', {}, domainBadges),
        el(
          'td',
          {},
          el(
            'span',
            { class: t.enabled ? 'badge badge-success' : 'badge badge-danger' },
            t.enabled ? '启用中' : '已禁用',
          ),
        ),
        el(
          'td',
          {},
          el('div', {}, fmtTime(t.last_used_at)),
          t.last_used_ip ? el('div', { class: 'muted small' }, `IP: ${t.last_used_ip}`) : null,
        ),
        el(
          'td',
          { class: 'text-right' },
          el('div', { class: 'btn-row-end' }, editBtn, toggleBtn, delBtn),
        ),
      ),
    );
  }
}

async function loadAuditLogs() {
  if (!isAdmin()) return;
  const tbody = $('#audit-tbody');
  if (!tbody) return;

  const action = $('#audit-action-filter')?.value || '';
  const q = ($('#audit-keyword')?.value || '').trim();
  const params = new URLSearchParams();
  if (action) params.set('action', action);
  if (q) params.set('q', q);
  const qs = params.toString();

  try {
    const data = await api(qs ? `/api/audit?${qs}` : '/api/audit');
    state.auditLogs = data.logs || [];
    tbody.replaceChildren();
    if (state.auditLogs.length === 0) {
      tbody.append(
        el('tr', {}, el('td', { colspan: 5, class: 'empty-cell' }, '暂无匹配的审计日志')),
      );
      return;
    }
    for (const item of state.auditLogs) {
      tbody.append(
        el(
          'tr',
          {},
          el('td', { class: 'small tabular-nums' }, fmtTime(item.created_at)),
          el(
            'td',
            {},
            el('strong', {}, item.username || '—'),
            el('div', { class: 'muted small' }, item.ip || '—'),
          ),
          el('td', {}, el('code', {}, item.action)),
          el('td', { class: 'record-val' }, item.target || '—'),
          el('td', { class: 'muted small' }, item.detail || '—'),
        ),
      );
    }
  } catch (err) {
    notify(err.message, true);
  }
}

function switchSysTab(subTab) {
  const admin = isAdmin();
  const target = !admin ? 'profile' : SYS_TABS.includes(subTab) ? subTab : 'users';
  state.activeSysTab = target;

  $$('[data-sys-tab]').forEach((btn) => {
    const name = btn.dataset.sysTab;
    if (name !== 'profile') {
      btn.hidden = !admin;
    } else {
      btn.hidden = false;
    }
    btn.classList.toggle('active', name === target);
  });

  for (const name of SYS_TABS) {
    const panel = $(`#sys-${name}`);
    if (panel) panel.hidden = name !== target;
  }

  const webhookCard = $('#webhook-admin-card');
  if (webhookCard) webhookCard.hidden = !admin;

  if (target === 'users') {
    loadUsers();
  } else if (target === 'tokens') {
    loadTokens();
  } else if (target === 'audit') {
    loadAuditLogs();
  } else if (target === 'profile') {
    syncWebhookTestBtn();
    if (admin) loadSettings();
  }
}

export function activateSystemView(preferredTab) {
  const admin = isAdmin();
  const target = !admin
    ? 'profile'
    : preferredTab || (SYS_TABS.includes(state.activeSysTab) ? state.activeSysTab : 'users');
  switchSysTab(target);
}

export function initSystem() {
  syncWebhookTestBtn();

  on('audit:changed', () => {
    if (state.activeTab === 'system' && state.activeSysTab === 'audit' && isAdmin()) {
      loadAuditLogs();
    }
  });

  $$('[data-sys-tab]').forEach((btn) => {
    btn.addEventListener('click', () => {
      switchSysTab(btn.dataset.sysTab);
    });
  });

  $('#new-user-btn')?.addEventListener('click', () => openUserEditor(null));
  $('#user-form-cancel')?.addEventListener('click', () => {
    const form = $('#user-form');
    if (form) form.hidden = true;
  });

  $('#user-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = ($('#user-edit-id')?.value || '').trim();
    const isMe = Boolean(id && state.user && state.user.id === id);
    const payload = {
      username: ($('#user-username')?.value || '').trim(),
      display_name: ($('#user-display')?.value || '').trim(),
      role: isMe ? state.user.role : $('#user-role')?.value || 'operator',
      password: $('#user-password')?.value || '',
      enabled: isMe ? true : Boolean($('#user-enabled')?.checked),
    };
    try {
      if (id) {
        await api(`/api/users/${id}`, { method: 'PUT', body: payload });
        if (isMe && state.user) {
          state.user.display_name = payload.display_name;
          const nameEl = $('#sidebar-user-name');
          if (nameEl) nameEl.textContent = state.user.display_name || state.user.username;
        }
        notify('用户信息已更新');
      } else {
        await api('/api/users', { method: 'POST', body: payload });
        notify('新用户已创建');
      }
      $('#user-form').hidden = true;
      await loadUsers();
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });

  $('#new-token-btn')?.addEventListener('click', () => openTokenEditor(null));
  $('#token-form-cancel')?.addEventListener('click', () => {
    const form = $('#token-form');
    if (form) form.hidden = true;
    if ($('#token-edit-id')) $('#token-edit-id').value = '';
  });

  $('#token-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const editId = ($('#token-edit-id')?.value || '').trim();
    const name = ($('#token-name')?.value || '').trim();
    const rawDomains = ($('#token-domains')?.value || '').trim();
    const allowed_domains = rawDomains
      ? rawDomains
          .split(/[\s,;]+/)
          .map((s) => s.trim())
          .filter(Boolean)
      : ['*'];

    try {
      if (editId) {
        await api(`/api/tokens/${editId}`, {
          method: 'PUT',
          body: { name, allowed_domains },
        });
        $('#token-form').hidden = true;
        $('#token-edit-id').value = '';
        notify('API 令牌已更新');
      } else {
        const res = await api('/api/tokens', {
          method: 'POST',
          body: { name, allowed_domains },
        });
        $('#token-form').hidden = true;
        renderTokenCreatedBanner(res.token, res.plaintext);
        notify('API 令牌已生成');
      }
      await loadTokens();
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });

  $('#audit-action-filter')?.addEventListener('change', () => loadAuditLogs());
  $('#audit-keyword')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      loadAuditLogs();
    }
  });
  $('#refresh-audit-btn')?.addEventListener('click', () => loadAuditLogs());

  $('#password-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      const res = await api('/api/password', {
        method: 'POST',
        body: {
          current: $('#pw-current')?.value || '',
          new: $('#pw-new')?.value || '',
        },
      });
      if (res && res.csrf) {
        state.csrf = res.csrf;
      }
      if ($('#pw-current')) $('#pw-current').value = '';
      if ($('#pw-new')) $('#pw-new').value = '';
      notify('个人登录密码已更新');
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });

  $('#webhook-url')?.addEventListener('input', () => syncWebhookTestBtn());

  $('#webhook-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/settings/webhook', {
        method: 'PUT',
        body: { webhook_url: ($('#webhook-url')?.value || '').trim() },
      });
      syncWebhookTestBtn();
      notify('Webhook 配置已保存');
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });

  $('#test-webhook-btn')?.addEventListener('click', async () => {
    const url = ($('#webhook-url')?.value || '').trim();
    if (!url) return;
    try {
      await api('/api/settings/webhook/test', {
        method: 'POST',
        body: { webhook_url: url },
      });
      notify('测试通知已发送，请检查接收端');
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });
}
