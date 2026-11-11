import { state, isViewer, on, emit } from './state.js';
import { api } from './api.js';
import { $, el, notify, copyText, editionLabel } from './ui.js';

let editingOriginalFqdn = '';

function recordFqdn(rr, zone) {
  const cleanRR = String(rr || '').trim();
  if (!zone) return cleanRR;
  return cleanRR === '@' || cleanRR === '' ? zone : `${cleanRR}.${zone}`;
}

function syncDNSRoleUI() {
  const viewer = isViewer();
  const addZoneToggle = $('#dns-add-zone-toggle');
  const newRecordBtn = $('#dns-new-record-btn');
  if (addZoneToggle) addZoneToggle.hidden = viewer;
  if (newRecordBtn) newRecordBtn.hidden = viewer;
  if (viewer) {
    const addZoneForm = $('#dns-add-zone-form');
    const recForm = $('#dns-record-form');
    if (addZoneForm) addZoneForm.hidden = true;
    if (recForm) recForm.hidden = true;
  }
}

function populateDNSAccountSelectors() {
  const dnsFilter = $('#dns-account-filter');
  if (dnsFilter) {
    const curFilter = dnsFilter.value;
    dnsFilter.replaceChildren(el('option', { value: '' }, '全部阿里云账户'));
    for (const a of state.accounts) {
      dnsFilter.append(el('option', { value: a.id }, `${a.name} (${editionLabel(a.edition)})`));
    }
    if ([...dnsFilter.options].some((o) => o.value === curFilter)) {
      dnsFilter.value = curFilter;
    }
  }

  const newZoneAcct = $('#new-zone-account');
  if (newZoneAcct) {
    const curAcct = newZoneAcct.value;
    newZoneAcct.replaceChildren();
    const enabledAccts = state.accounts.filter((a) => a.enabled);
    if (enabledAccts.length === 0) {
      newZoneAcct.append(el('option', { value: '' }, '暂无可用阿里云账户'));
    } else {
      for (const a of enabledAccts) {
        newZoneAcct.append(
          el('option', { value: a.id }, `${a.name} [${editionLabel(a.edition)}]`),
        );
      }
      if ([...newZoneAcct.options].some((o) => o.value === curAcct)) {
        newZoneAcct.value = curAcct;
      } else {
        const def = enabledAccts.find((a) => a.is_default);
        if (def) newZoneAcct.value = def.id;
      }
    }
  }
}

async function loadDNSRecords() {
  if (!state.currentZone) return;
  const tbody = $('#dns-records-body');
  if (!tbody) return;

  const typeFilter = $('#dns-type-filter')?.value || '';
  const keyword = ($('#dns-keyword')?.value || '').trim();
  const params = new URLSearchParams({
    zone: state.currentZone,
    page: String(state.dnsPage),
  });
  if (state.currentZoneAccount) params.set('account_id', state.currentZoneAccount);
  if (typeFilter) params.set('type', typeFilter);
  if (keyword) params.set('keyword', keyword);

  try {
    const data = await api(`/api/dns/records?${params.toString()}`);
    state.dnsRecords = data.records || [];
    state.dnsTotal = data.total || 0;
    renderDNSRecords(data.account_name, data.edition);
  } catch (err) {
    tbody.replaceChildren(
      el('tr', {}, el('td', { colspan: 6, class: 'empty-cell' }, err.message)),
    );
  }
}

function renderDNSRecords(acctName = '', edition = '') {
  const tbody = $('#dns-records-body');
  if (!tbody) return;
  tbody.replaceChildren();

  const viewer = isViewer();

  if (state.dnsRecords.length === 0) {
    tbody.append(
      el('tr', {}, el('td', { colspan: 6, class: 'empty-cell' }, '当前主域名下暂无匹配的解析记录。')),
    );
  } else {
    for (const r of state.dnsRecords) {
      const fqdn = recordFqdn(r.rr, state.currentZone);
      const isEntry = Boolean(state.hostname && fqdn === state.hostname);
      const enabled = String(r.status).toUpperCase() === 'ENABLE';
      const valText = r.type === 'MX' ? `[优先级 ${r.priority}] ${r.value}` : r.value;

      const toggleBtn = !viewer
        ? el(
            'button',
            {
              type: 'button',
              class: 'btn btn-secondary btn-sm',
              onclick: async () => {
                if (
                  isEntry &&
                  enabled &&
                  !confirm('⚠️ 警告：该记录为当前管理台入口域名，暂停解析可能导致无法访问管理台，确定继续？')
                ) {
                  return;
                }
                try {
                  await api(`/api/dns/records/${r.id}/status`, {
                    method: 'POST',
                    body: {
                      zone: state.currentZone,
                      account_id: state.currentZoneAccount,
                      enabled: !enabled,
                    },
                  });
                  notify(enabled ? '记录已暂停解析' : '记录已恢复启用');
                  await loadDNSRecords();
                  emit('audit:changed');
                } catch (err) {
                  notify(err.message, true);
                }
              },
            },
            enabled ? '暂停' : '启用',
          )
        : null;

      const editBtn = !viewer
        ? el(
            'button',
            {
              type: 'button',
              class: 'btn btn-secondary btn-sm',
              onclick: () => openRecordEditor(r),
            },
            '修改',
          )
        : null;

      const delBtn = !viewer
        ? el(
            'button',
            {
              type: 'button',
              class: 'btn btn-danger btn-sm',
              onclick: () => deleteDNSRecord(r, fqdn, isEntry),
            },
            '删除',
          )
        : null;

      tbody.append(
        el(
          'tr',
          {},
          el(
            'td',
            {},
            el('strong', {}, r.rr),
            el('div', { class: 'muted small' }, fqdn),
            isEntry ? el('span', { class: 'badge badge-info' }, '管理入口') : null,
          ),
          el('td', {}, el('span', { class: 'badge' }, r.type)),
          el(
            'td',
            {
              class: 'record-val',
              title: '点击复制记录值',
              onclick: () => copyText(r.value, '记录值'),
            },
            valText,
          ),
          el('td', { class: 'tabular-nums' }, `${r.ttl}s`),
          el(
            'td',
            {},
            el(
              'span',
              { class: enabled ? 'badge badge-success' : 'badge badge-warn' },
              enabled ? '启用' : '已暂停',
            ),
            r.remark ? el('div', { class: 'remark-sub' }, `备注: ${r.remark}`) : null,
          ),
          el(
            'td',
            { class: 'text-right' },
            el('div', { class: 'btn-row-end' }, toggleBtn, editBtn, delBtn),
          ),
        ),
      );
    }
  }

  const pageBar = $('#dns-pagination');
  if (!pageBar) return;
  pageBar.replaceChildren();

  const totalPages = Math.max(1, Math.ceil(state.dnsTotal / 100));
  const acctInfo = acctName ? ` · 所属账户: ${acctName} (${editionLabel(edition)})` : '';

  pageBar.append(
    el('span', {}, `共 ${state.dnsTotal} 条记录 · 第 ${state.dnsPage}/${totalPages} 页${acctInfo}`),
    el(
      'div',
      { class: 'btn-row' },
      el(
        'button',
        {
          type: 'button',
          class: 'btn btn-secondary btn-sm',
          disabled: state.dnsPage <= 1,
          onclick: () => {
            state.dnsPage--;
            loadDNSRecords();
          },
        },
        '上一页',
      ),
      el(
        'button',
        {
          type: 'button',
          class: 'btn btn-secondary btn-sm',
          disabled: state.dnsPage >= totalPages,
          onclick: () => {
            state.dnsPage++;
            loadDNSRecords();
          },
        },
        '下一页',
      ),
    ),
  );
}

function openRecordEditor(rec = null) {
  if (isViewer()) return;
  const form = $('#dns-record-form');
  if (!form) return;
  form.hidden = false;

  const fqdn = rec ? recordFqdn(rec.rr, state.currentZone) : '';
  editingOriginalFqdn = fqdn;

  $('#dns-form-title').textContent = rec
    ? `修改解析记录 (${fqdn})`
    : `新增解析记录 (${state.currentZone})`;
  $('#dns-record-id').value = rec ? rec.id : '';
  $('#dns-rr').value = rec ? rec.rr : '';
  $('#dns-type').value = rec ? rec.type : 'A';
  $('#dns-value').value = rec ? rec.value : '';
  $('#dns-ttl').value = rec ? String(rec.ttl) : '600';
  $('#dns-priority').value = rec && rec.priority ? String(rec.priority) : '10';
  $('#dns-remark').value = rec && rec.remark ? rec.remark : '';
  $('#dns-priority-wrap').hidden = $('#dns-type').value !== 'MX';
  $('#dns-rr').focus();
}

async function deleteDNSRecord(rec, fqdn, isEntry) {
  const warn = isEntry
    ? '\n⚠️ 警告：该记录对应当前管理台入口域名，删除后可能导致无法访问管理台！'
    : '';
  if (!confirm(`确认删除解析记录 ${fqdn} [${rec.type} -> ${rec.value}] 吗？${warn}`)) return;
  try {
    await api(`/api/dns/records/${rec.id}`, {
      method: 'DELETE',
      body: { zone: state.currentZone, account_id: state.currentZoneAccount },
    });
    notify('解析记录已删除');
    await loadDNSRecords();
    emit('audit:changed');
  } catch (err) {
    notify(err.message, true);
  }
}

export async function loadDNSZones(refresh = false) {
  syncDNSRoleUI();
  populateDNSAccountSelectors();
  try {
    const acctFilter = $('#dns-account-filter')?.value || '';
    const params = new URLSearchParams();
    if (acctFilter) params.set('account_id', acctFilter);
    if (refresh) params.set('refresh', '1');
    const qs = params.toString();
    const data = await api(qs ? `/api/dns/zones?${qs}` : '/api/dns/zones');
    state.zoneItems = data.items || [];

    if (refresh) {
      const acctData = await api('/api/accounts');
      state.accounts = acctData.accounts || [];
      emit('accounts:changed', { source: 'dns' });
    }

    const sel = $('#dns-zone-select');
    if (!sel) return;
    sel.replaceChildren();

    if (state.zoneItems.length === 0) {
      state.currentZone = '';
      state.currentZoneAccount = '';
      sel.append(el('option', { value: '' }, '暂无托管域名'));
      $('#dns-records-body')?.replaceChildren(
        el(
          'tr',
          {},
          el(
            'td',
            { colspan: 6, class: 'empty-cell' },
            '未找到托管主域名，请先在“阿里云账户”中同步或添加账户。',
          ),
        ),
      );
      $('#dns-pagination')?.replaceChildren();
      return;
    }

    for (const item of state.zoneItems) {
      const key = `${item.zone}|${item.account_id}`;
      sel.append(
        el(
          'option',
          { value: key },
          `${item.zone} [${item.account_name} · ${editionLabel(item.edition)}]`,
        ),
      );
    }

    const currentKey = `${state.currentZone}|${state.currentZoneAccount}`;
    const matched =
      state.zoneItems.find((i) => `${i.zone}|${i.account_id}` === currentKey) || state.zoneItems[0];
    state.currentZone = matched.zone;
    state.currentZoneAccount = matched.account_id;
    sel.value = `${matched.zone}|${matched.account_id}`;
    state.dnsPage = 1;
    await loadDNSRecords();
  } catch (err) {
    $('#dns-records-body')?.replaceChildren(
      el('tr', {}, el('td', { colspan: 6, class: 'empty-cell' }, err.message)),
    );
  }
}

export function initDNS() {
  on('accounts:changed', () => {
    syncDNSRoleUI();
    populateDNSAccountSelectors();
  });

  $('#dns-account-filter')?.addEventListener('change', () => loadDNSZones(false));

  $('#dns-zone-select')?.addEventListener('change', (e) => {
    const [z, acctId] = (e.target.value || '|').split('|');
    state.currentZone = z || '';
    state.currentZoneAccount = acctId || '';
    state.dnsPage = 1;
    $('#dns-record-form').hidden = true;
    loadDNSRecords();
  });

  $('#dns-refresh-zones')?.addEventListener('click', () => loadDNSZones(true));

  $('#dns-search-btn')?.addEventListener('click', () => {
    state.dnsPage = 1;
    loadDNSRecords();
  });

  $('#dns-type-filter')?.addEventListener('change', () => {
    state.dnsPage = 1;
    loadDNSRecords();
  });

  $('#dns-keyword')?.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      state.dnsPage = 1;
      loadDNSRecords();
    }
  });

  $('#dns-export-btn')?.addEventListener('click', () => {
    if (!state.currentZone) {
      notify('请先选择要导出的托管主域名', true);
      return;
    }
    const params = new URLSearchParams({ zone: state.currentZone });
    if (state.currentZoneAccount) params.set('account_id', state.currentZoneAccount);
    window.location.href = `/api/dns/export?${params.toString()}`;
  });

  $('#dns-add-zone-toggle')?.addEventListener('click', () => {
    const form = $('#dns-add-zone-form');
    if (!form) return;
    form.hidden = !form.hidden;
    const resBox = $('#new-zone-result');
    if (resBox) resBox.hidden = true;
    if (!form.hidden) {
      $('#new-zone-input')?.focus();
    }
  });

  $('#dns-add-zone-cancel')?.addEventListener('click', () => {
    const form = $('#dns-add-zone-form');
    const resBox = $('#new-zone-result');
    if (form) form.hidden = true;
    if (resBox) resBox.hidden = true;
  });

  $('#dns-add-zone-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domainName = ($('#new-zone-input')?.value || '').trim();
    const accountId = $('#new-zone-account')?.value || '';
    try {
      const res = await api('/api/dns/zones', {
        method: 'POST',
        body: { domain: domainName, account_id: accountId },
      });
      if ($('#new-zone-input')) $('#new-zone-input').value = '';

      const nsList = res.nameservers || [];
      const resBox = $('#new-zone-result');
      if (resBox) {
        resBox.replaceChildren(
          el(
            'div',
            {},
            el('strong', {}, `✓ 已在 [${res.account_name || '阿里云账户'}] 成功接入主域名 ${res.domain}`),
          ),
          nsList.length > 0
            ? el(
                'div',
                { class: 'mt-xs' },
                '请前往域名注册商处将 NS 服务器修改为：',
                el('code', {}, nsList.join(', ')),
              )
            : el('div', { class: 'mt-xs' }, '域名已接入，请前往注册商确认阿里云 NS 服务器配置。'),
        );
        resBox.hidden = false;
      }
      const addForm = $('#dns-add-zone-form');
      if (addForm) addForm.hidden = false;

      state.currentZone = res.domain;
      state.currentZoneAccount = res.account_id || accountId;
      notify(`主域名 ${res.domain} 已成功接入`);
      await loadDNSZones(true);
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });

  $('#dns-new-record-btn')?.addEventListener('click', () => {
    if (!state.currentZone) {
      notify('请先选择托管主域名', true);
      return;
    }
    openRecordEditor(null);
  });

  $('#dns-form-cancel')?.addEventListener('click', () => {
    const form = $('#dns-record-form');
    if (form) form.hidden = true;
    editingOriginalFqdn = '';
  });

  $('#dns-type')?.addEventListener('change', (e) => {
    const wrap = $('#dns-priority-wrap');
    if (wrap) wrap.hidden = e.target.value !== 'MX';
  });

  $('#dns-record-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const id = ($('#dns-record-id')?.value || '').trim();
    const rr = ($('#dns-rr')?.value || '').trim();
    const type = $('#dns-type')?.value || 'A';
    const newFqdn = recordFqdn(rr, state.currentZone);

    if (id && state.hostname) {
      const existingRec = state.dnsRecords.find((r) => r.id === id);
      const origFqdn = existingRec
        ? recordFqdn(existingRec.rr, state.currentZone)
        : editingOriginalFqdn;
      if (origFqdn === state.hostname || newFqdn === state.hostname) {
        if (
          !confirm(
            '⚠️ 警告：该记录涉及当前管理台入口域名，修改解析可能导致无法访问管理台，确定保存修改吗？',
          )
        ) {
          return;
        }
      }
    }

    const payload = {
      zone: state.currentZone,
      account_id: state.currentZoneAccount,
      rr,
      type,
      value: ($('#dns-value')?.value || '').trim(),
      ttl: Number($('#dns-ttl')?.value || 600),
      remark: ($('#dns-remark')?.value || '').trim(),
    };
    if (type === 'MX') {
      payload.priority = Number($('#dns-priority')?.value || 10);
    }

    try {
      if (id) {
        await api(`/api/dns/records/${id}`, { method: 'PUT', body: payload });
        notify('解析记录已更新');
      } else {
        await api('/api/dns/records', { method: 'POST', body: payload });
        notify('解析记录已添加');
      }
      const form = $('#dns-record-form');
      if (form) form.hidden = true;
      editingOriginalFqdn = '';
      await loadDNSRecords();
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });
}
