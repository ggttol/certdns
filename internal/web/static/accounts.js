import { state, isAdmin, isViewer, on, emit } from './state.js';
import { api } from './api.js';
import { $, el, notify, fmtTime, editionLabel } from './ui.js';

function syncAccountsRoleUI() {
  const sideCard = $('#account-side-card');
  const syncBtn = $('#sync-all-accounts-btn');
  if (sideCard) sideCard.hidden = !isAdmin();
  if (syncBtn) syncBtn.hidden = isViewer();
}

function resetAccountForm() {
  const title = $('#account-form-title');
  const resetBtn = $('#account-form-reset');
  const secretInput = $('#acct-key-secret');
  const secretHint = $('#acct-secret-hint');
  const customWrap = $('#acct-custom-wrap');

  if (title) title.textContent = '新增阿里云账户';
  if (resetBtn) resetBtn.hidden = true;
  if ($('#acct-id')) $('#acct-id').value = '';
  if ($('#acct-name')) $('#acct-name').value = '';
  if ($('#acct-edition')) $('#acct-edition').value = 'cn';
  if ($('#acct-region')) $('#acct-region').value = '';
  if ($('#acct-endpoint')) $('#acct-endpoint').value = '';
  if (customWrap) customWrap.hidden = true;
  if ($('#acct-key-id')) $('#acct-key-id').value = '';
  if (secretInput) {
    secretInput.value = '';
    secretInput.required = true;
  }
  if (secretHint) secretHint.textContent = '(必填)';
  if ($('#acct-email')) $('#acct-email').value = '';
  if ($('#acct-default')) $('#acct-default').checked = false;
  if ($('#acct-enabled')) $('#acct-enabled').checked = true;
}

function editAccount(a) {
  if (!isAdmin()) return;
  const title = $('#account-form-title');
  const resetBtn = $('#account-form-reset');
  const secretInput = $('#acct-key-secret');
  const secretHint = $('#acct-secret-hint');
  const customWrap = $('#acct-custom-wrap');

  if (title) title.textContent = `编辑账户 · ${a.name}`;
  if (resetBtn) resetBtn.hidden = false;
  if ($('#acct-id')) $('#acct-id').value = a.id;
  if ($('#acct-name')) $('#acct-name').value = a.name || '';
  if ($('#acct-edition')) $('#acct-edition').value = a.edition || 'cn';
  if ($('#acct-region')) $('#acct-region').value = a.region_id || '';
  if ($('#acct-endpoint')) $('#acct-endpoint').value = a.endpoint || '';
  if (customWrap) customWrap.hidden = a.edition !== 'custom';
  if ($('#acct-key-id')) $('#acct-key-id').value = a.access_key_id || '';
  if (secretInput) {
    secretInput.value = '';
    secretInput.required = false;
  }
  if (secretHint) secretHint.textContent = '(留空表示保留原 Secret)';
  if ($('#acct-email')) $('#acct-email').value = a.email || '';
  if ($('#acct-default')) $('#acct-default').checked = Boolean(a.is_default);
  if ($('#acct-enabled')) $('#acct-enabled').checked = Boolean(a.enabled);
  $('#acct-name')?.focus();
}

function renderAccountsList() {
  const wrap = $('#accounts-list');
  if (!wrap) return;
  wrap.replaceChildren();

  const navBadge = $('#nav-acct-badge');
  if (navBadge) navBadge.textContent = String(state.accounts.length);

  if (state.accounts.length === 0) {
    wrap.append(
      el(
        'div',
        { class: 'empty-cell' },
        isAdmin()
          ? '尚未配置阿里云 DNS 账户，请在右侧表单中添加中国站或国际站账户。'
          : '尚未配置任何阿里云 DNS 账户。',
      ),
    );
    return;
  }

  const admin = isAdmin();
  const viewer = isViewer();

  for (const a of state.accounts) {
    const badges = [
      el(
        'span',
        { class: a.edition === 'intl' ? 'badge badge-blue' : 'badge badge-info' },
        editionLabel(a.edition),
      ),
    ];
    if (a.is_default) badges.push(el('span', { class: 'badge badge-success' }, '默认账户'));
    if (!a.enabled) badges.push(el('span', { class: 'badge badge-warn' }, '已停用'));

    const zones = a.cached_zones || [];
    const zonesText = zones.length > 0 ? zones.join(', ') : '暂未同步或无托管域名';

    const testBtn = !viewer
      ? el(
          'button',
          {
            type: 'button',
            class: 'btn btn-secondary btn-sm',
            onclick: async () => {
              try {
                notify(`正在连接 ${a.name} 并同步托管域名…`);
                const res = await api(`/api/accounts/${a.id}/test`, { method: 'POST', body: {} });
                const cnt = Array.isArray(res.zones) ? res.zones.length : 0;
                notify(`同步成功：共读取 ${cnt} 个托管域名`);
                await loadAccounts();
                emit('audit:changed');
              } catch (err) {
                notify(err.message, true);
                await loadAccounts();
              }
            },
          },
          '测试并同步域名',
        )
      : null;

    const editBtn = admin
      ? el(
          'button',
          {
            type: 'button',
            class: 'btn btn-secondary btn-sm',
            onclick: () => editAccount(a),
          },
          '编辑',
        )
      : null;

    const deleteBtn = admin
      ? el(
          'button',
          {
            type: 'button',
            class: 'btn btn-danger btn-sm',
            onclick: async () => {
              if (!confirm(`确定删除阿里云账户 [${a.name}] 吗？`)) return;
              try {
                await api(`/api/accounts/${a.id}`, { method: 'DELETE' });
                if ($('#acct-id')?.value === a.id) {
                  resetAccountForm();
                }
                notify('阿里云账户已删除');
                await loadAccounts();
                emit('audit:changed');
              } catch (err) {
                notify(err.message, true);
              }
            },
          },
          '删除',
        )
      : null;

    wrap.append(
      el(
        'div',
        { class: 'cert-item' },
        el(
          'div',
          { class: 'cert-top' },
          el('div', { class: 'cert-domains' }, el('strong', { class: 'item-title' }, a.name)),
          el('div', { class: 'btn-row' }, ...badges),
        ),
        el(
          'div',
          { class: 'cert-meta' },
          el('span', {}, `AccessKey: ${a.masked_key_id || a.access_key_id || '—'}`),
          el('span', {}, `地域: ${a.region_id || '—'}`),
          el('span', {}, `Endpoint: ${a.endpoint || '—'}`),
          a.email ? el('span', {}, `邮箱: ${a.email}`) : null,
        ),
        el('div', { class: 'muted small' }, `托管域名 (${zones.length}): ${zonesText}`),
        a.last_error ? el('p', { class: 'error-banner' }, a.last_error) : null,
        el(
          'div',
          { class: 'cert-actions' },
          el('span', { class: 'muted small' }, `上次检测: ${fmtTime(a.last_checked_at)}`),
          el('div', { class: 'btn-row' }, testBtn, editBtn, deleteBtn),
        ),
      ),
    );
  }
}

export async function loadAccounts() {
  syncAccountsRoleUI();
  try {
    const data = await api('/api/accounts');
    state.accounts = data.accounts || [];
    renderAccountsList();
    emit('accounts:changed', { source: 'accounts' });
  } catch (err) {
    notify(err.message, true);
  }
}

export function initAccounts() {
  resetAccountForm();

  on('accounts:changed', (detail) => {
    syncAccountsRoleUI();
    if (!detail || detail.source !== 'accounts') {
      renderAccountsList();
    }
  });

  $('#acct-edition')?.addEventListener('change', (e) => {
    const wrap = $('#acct-custom-wrap');
    if (wrap) wrap.hidden = e.target.value !== 'custom';
  });

  $('#account-form-reset')?.addEventListener('click', () => resetAccountForm());

  $('#sync-all-accounts-btn')?.addEventListener('click', async () => {
    try {
      notify('正在同步全部阿里云账户的托管域名…');
      const res = await api('/api/accounts/sync-all', { method: 'POST', body: {} });
      if (Array.isArray(res.accounts)) {
        state.accounts = res.accounts;
        renderAccountsList();
        emit('accounts:changed', { source: 'accounts' });
      } else {
        await loadAccounts();
      }
      emit('audit:changed');
      notify('全部阿里云账户同步完成');
    } catch (err) {
      notify(err.message, true);
    }
  });

  $('#account-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = ($('#acct-id')?.value || '').trim();
    const payload = {
      name: ($('#acct-name')?.value || '').trim(),
      edition: $('#acct-edition')?.value || 'cn',
      region_id: ($('#acct-region')?.value || '').trim(),
      endpoint: ($('#acct-endpoint')?.value || '').trim(),
      access_key_id: ($('#acct-key-id')?.value || '').trim(),
      access_key_secret: $('#acct-key-secret')?.value || '',
      email: ($('#acct-email')?.value || '').trim(),
      is_default: Boolean($('#acct-default')?.checked),
      enabled: Boolean($('#acct-enabled')?.checked),
    };
    try {
      if (id) {
        await api(`/api/accounts/${id}`, { method: 'PUT', body: payload });
        notify('阿里云账户已更新');
      } else {
        await api('/api/accounts', { method: 'POST', body: payload });
        notify('阿里云账户已添加并完成同步');
      }
      resetAccountForm();
      await loadAccounts();
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });
}
