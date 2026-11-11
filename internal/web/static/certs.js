import { state, isViewer, on, emit } from './state.js';
import { api } from './api.js';
import {
  $,
  $$,
  el,
  notify,
  showModal,
  closeModal,
  copyText,
  fmtTime,
  statusBadge,
  editionLabel,
} from './ui.js';

function isExpiringCert(c) {
  return (
    c.status === 'valid' &&
    c.days_left !== null &&
    c.days_left !== undefined &&
    c.days_left >= 0 &&
    c.days_left <= 30
  );
}

function isAbnormalCert(c) {
  return c.status === 'expired' || c.status === 'error';
}

function isPendingCert(c) {
  return (
    Boolean(c.active_job) ||
    c.status === 'queued' ||
    c.status === 'issuing' ||
    c.status === 'renewing' ||
    c.status === 'running'
  );
}

function syncCertRoleUI() {
  const viewer = isViewer();
  const sideCard = $('#cert-side-card');
  const loadZonesBtn = $('#load-zones-btn');
  if (sideCard) sideCard.hidden = viewer;
  if (loadZonesBtn) loadZonesBtn.hidden = viewer;
}

function populateCertAccountSelectors() {
  const issueSel = $('#issue-account');
  if (issueSel) {
    const curIssue = issueSel.value;
    issueSel.replaceChildren(
      el('option', { value: '' }, '自动匹配域名所属阿里云账户 (支持跨账户合并签发)'),
    );
    for (const a of state.accounts) {
      if (!a.enabled) continue;
      issueSel.append(el('option', { value: a.id }, `${a.name} [${editionLabel(a.edition)}]`));
    }
    if ([...issueSel.options].some((o) => o.value === curIssue)) {
      issueSel.value = curIssue;
    }
  }

  const filterSel = $('#cert-account-filter');
  if (filterSel) {
    const curFilter = filterSel.value;
    filterSel.replaceChildren(el('option', { value: '' }, '全部阿里云账户'));
    for (const a of state.accounts) {
      filterSel.append(el('option', { value: a.id }, `${a.name} (${editionLabel(a.edition)})`));
    }
    if ([...filterSel.options].some((o) => o.value === curFilter)) {
      filterSel.value = curFilter;
    }
  }
}

function appendDomainToIssue(items) {
  const ta = $('#issue-domains');
  if (!ta) return;
  const existing = ta.value
    .split(/[\n,\s]+/)
    .map((s) => s.trim())
    .filter(Boolean);
  for (const it of items) {
    if (!existing.includes(it)) existing.push(it);
  }
  ta.value = existing.join('\n');
}

export function renderQuickZones() {
  const box = $('#quick-zones');
  if (!box) return;
  box.replaceChildren();

  const pairs = [];
  for (const a of state.accounts) {
    if (!a.enabled) continue;
    for (const z of a.cached_zones || []) {
      pairs.push({ zone: z, account: a.name });
    }
  }

  if (pairs.length === 0) {
    box.append(
      el('span', { class: 'muted small' }, '暂无已缓存域名，可点击“同步全部账户域名”或直接输入'),
    );
    return;
  }

  for (const p of pairs) {
    box.append(
      el(
        'button',
        {
          type: 'button',
          class: 'chip',
          title: `所属账户: ${p.account}`,
          onclick: () => appendDomainToIssue([p.zone, `*.${p.zone}`]),
        },
        `＋ ${p.zone} + *.${p.zone}`,
      ),
    );
  }
}

function renderCertStats() {
  const total = state.certs.length;
  const valid = state.certs.filter((c) => c.status === 'valid').length;
  const expiring = state.certs.filter(isExpiringCert).length;
  const abnormal = state.certs.filter(isAbnormalCert).length;

  const statTotal = $('#stat-total');
  const statValid = $('#stat-valid');
  const statExpiring = $('#stat-expiring');
  const statAbnormal = $('#stat-abnormal');
  const navBadge = $('#nav-cert-badge');

  if (statTotal) statTotal.textContent = String(total);
  if (statValid) statValid.textContent = String(valid);
  if (statExpiring) statExpiring.textContent = String(expiring);
  if (statAbnormal) statAbnormal.textContent = String(abnormal);
  if (navBadge) navBadge.textContent = String(total);
}

function filterCerts(certs) {
  const q = ($('#cert-search')?.value || '').trim().toLowerCase();
  const statusFilter = $('#cert-status-filter')?.value || '';
  const acctFilter = $('#cert-account-filter')?.value || '';

  return certs.filter((c) => {
    if (statusFilter === 'valid' && c.status !== 'valid') return false;
    if (statusFilter === 'expiring' && !isExpiringCert(c)) return false;
    if (statusFilter === 'abnormal' && !isAbnormalCert(c)) return false;
    if (statusFilter === 'pending' && !isPendingCert(c)) return false;

    if (acctFilter && (c.account_id || '') !== acctFilter) return false;

    if (q) {
      const hay = [
        ...(c.domains || []),
        c.remark || '',
        c.issuer || '',
        c.id || '',
        c.account_name || '',
      ]
        .join(' ')
        .toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
}

function renderCertificates() {
  const wrap = $('#certs-list');
  if (!wrap) return;
  wrap.replaceChildren();

  if (state.certs.length === 0) {
    wrap.append(
      el(
        'div',
        { class: 'empty-cell' },
        isViewer()
          ? '当前尚未托管任何 TLS 证书。'
          : '尚未托管任何证书，可在右侧面板提交签发或上传已有证书。',
      ),
    );
    return;
  }

  const list = filterCerts(state.certs);
  if (list.length === 0) {
    wrap.append(el('div', { class: 'empty-cell' }, '未找到符合当前筛选条件的证书。'));
    return;
  }

  const viewer = isViewer();

  for (const c of list) {
    const domainPills = (c.domains || []).map((d) => el('span', { class: 'domain-pill' }, d));
    const badges = [statusBadge(c.status, c.days_left)];
    if (c.source === 'upload') {
      badges.push(el('span', { class: 'badge badge-blue' }, '外部导入'));
    } else if (c.staging) {
      badges.push(el('span', { class: 'badge badge-warn' }, 'Staging 测试'));
    }
    if (c.key_type) {
      badges.push(el('span', { class: 'badge' }, c.key_type));
    }
    if (c.account_name) {
      badges.push(el('span', { class: 'badge' }, `云账户: ${c.account_name}`));
    }
    if (c.in_use) {
      badges.push(el('span', { class: 'badge badge-info' }, `管理入口: ${c.used_by}`));
    }

    const autoRenewNode =
      c.source !== 'upload'
        ? el(
            'label',
            { class: 'checkbox-inline' },
            el('input', {
              type: 'checkbox',
              checked: Boolean(c.auto_renew),
              disabled: viewer,
              onchange: async (e) => {
                const next = e.target.checked;
                try {
                  await api(`/api/certificates/${c.id}`, {
                    method: 'PUT',
                    body: { auto_renew: next },
                  });
                  notify(next ? '已开启自动续期' : '已关闭自动续期');
                  await loadCertificates();
                  emit('certs:changed', { loaded: true });
                  emit('audit:changed');
                } catch (err) {
                  e.target.checked = !next;
                  notify(err.message, true);
                }
              },
            }),
            el('span', {}, '到期前 30 天自动续期'),
          )
        : el('span', { class: 'muted small' }, '外部导入证书（手动更新）');

    const detailBtn = el(
      'button',
      {
        type: 'button',
        class: 'btn btn-secondary btn-sm',
        onclick: () => openCertDetailModal(c.id),
      },
      viewer ? '证书详情' : '详情 / 复制 PEM',
    );

    const editBtn = !viewer
      ? el(
          'button',
          {
            type: 'button',
            class: 'btn btn-secondary btn-sm',
            onclick: () => openCertEditModal(c),
          },
          '编辑配置',
        )
      : null;

    const dlNginxBtn =
      !viewer && c.not_after
        ? el(
            'a',
            {
              class: 'btn btn-secondary btn-sm',
              href: `/api/certificates/${c.id}/download?format=nginx`,
              title: '含 fullchain.pem 与 privkey.pem',
            },
            '下载 Nginx 包',
          )
        : null;

    const renewBtn =
      !viewer && c.source !== 'upload'
        ? el(
            'button',
            {
              type: 'button',
              class: 'btn btn-secondary btn-sm',
              disabled: Boolean(c.active_job),
              onclick: async () => {
                try {
                  const res = await api(`/api/certificates/${c.id}/renew`, {
                    method: 'POST',
                    body: {},
                  });
                  notify('已加入续期队列');
                  await loadCertificates();
                  emit('certs:changed', { loaded: true });
                  emit('audit:changed');
                  if (res.job_id) emit('job:open', res.job_id);
                } catch (err) {
                  notify(err.message, true);
                }
              },
            },
            c.active_job ? '执行中…' : '立即续期',
          )
        : null;

    const deleteBtn = !viewer
      ? el(
          'button',
          {
            type: 'button',
            class: 'btn btn-danger btn-sm',
            disabled: Boolean(c.in_use || c.active_job),
            title: c.in_use ? `此证书正在保护管理入口 ${c.used_by}，不可删除` : '删除此证书',
            onclick: async () => {
              if (!confirm(`确定删除证书 [${(c.domains || []).join(', ')}] 吗？此操作不可撤销。`)) {
                return;
              }
              try {
                await api(`/api/certificates/${c.id}`, { method: 'DELETE' });
                notify('证书已删除');
                await loadCertificates();
                emit('certs:changed', { loaded: true });
                emit('audit:changed');
              } catch (err) {
                notify(err.message, true);
              }
            },
          },
          c.in_use ? '使用中保护' : '删除',
        )
      : null;

    wrap.append(
      el(
        'div',
        { class: 'cert-item' },
        el(
          'div',
          { class: 'cert-top' },
          el('div', { class: 'cert-domains' }, ...domainPills),
          el('div', { class: 'btn-row' }, ...badges),
        ),
        el(
          'div',
          { class: 'cert-meta' },
          el('span', {}, `到期时间: ${fmtTime(c.not_after)}`),
          c.issuer ? el('span', {}, `颁发机构: ${c.issuer}`) : null,
          c.remark ? el('span', {}, `备注: ${c.remark}`) : null,
          el('span', {}, `ID: ${c.id.slice(0, 8)}`),
        ),
        c.last_error ? el('p', { class: 'error-banner' }, c.last_error) : null,
        el(
          'div',
          { class: 'cert-actions' },
          autoRenewNode,
          el('div', { class: 'btn-row' }, detailBtn, editBtn, dlNginxBtn, renewBtn, deleteBtn),
        ),
      ),
    );
  }
}

async function openCertDetailModal(id) {
  try {
    const data = await api(`/api/certificates/${id}`);
    const c = data.certificate;
    const x = data.x509;
    const pem = data.pem;
    const viewer = isViewer();

    const dl = el(
      'dl',
      { class: 'kv-grid' },
      el('dt', {}, '证书 ID'),
      el('dd', {}, c.id),
      el('dt', {}, '包含域名 (SAN)'),
      el('dd', {}, (x?.sans || c.domains || []).join(', ')),
      el('dt', {}, '来源 / 环境'),
      el(
        'dd',
        {},
        c.source === 'upload'
          ? '外部上传导入'
          : c.staging
            ? "Let's Encrypt Staging (测试)"
            : "Let's Encrypt Production (正式)",
      ),
      el('dt', {}, '颁发机构'),
      el('dd', {}, x?.issuer || c.issuer || '—'),
      el('dt', {}, '生效时间'),
      el('dd', {}, fmtTime(x?.not_before || c.not_before)),
      el('dt', {}, '到期时间'),
      el('dd', {}, fmtTime(x?.not_after || c.not_after)),
      el('dt', {}, '密钥 / 签名算法'),
      el('dd', {}, x ? `${x.key_type} / ${x.signature}` : c.key_type || '—'),
      el('dt', {}, '序列号 (Hex)'),
      el('dd', {}, x?.serial || '—'),
      el('dt', {}, 'SHA-256 指纹'),
      el('dd', {}, x?.sha256 || c.sha256 || '—'),
      c.remark ? [el('dt', {}, '备注标签'), el('dd', {}, c.remark)] : null,
    );

    const nodes = [dl];

    if (!viewer && pem) {
      nodes.push(
        el(
          'div',
          { class: 'btn-row' },
          el(
            'a',
            {
              class: 'btn btn-primary btn-sm',
              href: `/api/certificates/${c.id}/download?format=nginx`,
            },
            '下载 Nginx 证书包 (ZIP)',
          ),
          el(
            'a',
            {
              class: 'btn btn-secondary btn-sm',
              href: `/api/certificates/${c.id}/download?format=apache`,
            },
            '下载 Apache 证书包 (ZIP)',
          ),
          el(
            'a',
            {
              class: 'btn btn-secondary btn-sm',
              href: `/api/certificates/${c.id}/download?format=all`,
            },
            '下载全量证书包 (ZIP)',
          ),
        ),
        el(
          'div',
          { class: 'pem-box' },
          el(
            'div',
            { class: 'pem-box-header' },
            el('span', {}, '证书链 (fullchain.pem)'),
            el(
              'button',
              {
                type: 'button',
                class: 'btn btn-secondary btn-sm',
                onclick: () => copyText(pem.fullchain, '证书链 fullchain.pem'),
              },
              '一键复制证书链',
            ),
          ),
          el(
            'textarea',
            { class: 'mono-textarea', rows: 5, readonly: true },
            pem.fullchain,
          ),
        ),
        el(
          'div',
          { class: 'pem-box' },
          el(
            'div',
            { class: 'pem-box-header' },
            el('span', {}, '私钥 (privkey.pem)'),
            el(
              'button',
              {
                type: 'button',
                class: 'btn btn-secondary btn-sm',
                onclick: () => copyText(pem.privkey, '私钥 privkey.pem'),
              },
              '一键复制私钥',
            ),
          ),
          el(
            'textarea',
            { class: 'mono-textarea', rows: 5, readonly: true },
            pem.privkey,
          ),
        ),
      );
    }

    const titleDomain = (c.domains && c.domains[0]) || c.id.slice(0, 8);
    showModal(`证书详情 · ${titleDomain}`, el('div', { class: 'stack-form' }, ...nodes));
  } catch (err) {
    notify(err.message, true);
  }
}

function openCertEditModal(c) {
  const isUpload = c.source === 'upload';

  const remarkInput = el('input', {
    type: 'text',
    id: 'edit-cert-remark',
    value: c.remark || '',
    maxlength: 200,
    placeholder: '如：生产主站 / 边缘网关',
  });

  let acctSelect = null;
  let autoRenewCheck = null;

  if (!isUpload) {
    acctSelect = el(
      'select',
      { id: 'edit-cert-account', class: 'select-input' },
      el('option', { value: '' }, '自动匹配域名所属阿里云账户 (支持跨账户合并签发)'),
    );
    for (const a of state.accounts) {
      if (!a.enabled && a.id !== c.account_id) continue;
      const suffix = a.enabled ? editionLabel(a.edition) : `${editionLabel(a.edition)} · 已停用`;
      acctSelect.append(el('option', { value: a.id }, `${a.name} [${suffix}]`));
    }
    acctSelect.value = c.account_id || '';

    autoRenewCheck = el('input', {
      type: 'checkbox',
      id: 'edit-cert-autorenew',
      checked: Boolean(c.auto_renew),
    });
  }

  const form = el(
    'form',
    {
      class: 'stack-form',
      onsubmit: async (e) => {
        e.preventDefault();
        const body = {
          remark: remarkInput.value.trim(),
        };
        if (!isUpload) {
          body.account_id = acctSelect.value;
          body.auto_renew = autoRenewCheck.checked;
        }
        try {
          await api(`/api/certificates/${c.id}`, {
            method: 'PUT',
            body,
          });
          notify('证书配置已更新');
          closeModal();
          await loadCertificates();
          emit('certs:changed', { loaded: true });
          emit('audit:changed');
        } catch (err) {
          notify(err.message, true);
        }
      },
    },
    el(
      'div',
      {},
      el('label', { for: 'edit-cert-remark' }, '备注标签'),
      remarkInput,
    ),
    !isUpload
      ? el(
          'div',
          {},
          el('label', { for: 'edit-cert-account' }, 'DNS 验证阿里云账户'),
          acctSelect,
          el(
            'p',
            { class: 'help-text' },
            '续期时优先使用指定账户；选择“自动匹配”可根据各 SAN 域名自动路由对应账户。',
          ),
        )
      : el('p', { class: 'muted small' }, '外部导入证书不支持配置 ACME 账户与自动续期。'),
    !isUpload
      ? el(
          'label',
          { class: 'checkbox-inline', for: 'edit-cert-autorenew' },
          autoRenewCheck,
          el('span', {}, '开启到期前 30 天自动续期'),
        )
      : null,
    el(
      'div',
      { class: 'btn-row-end' },
      el(
        'button',
        {
          type: 'button',
          class: 'btn btn-ghost btn-sm',
          onclick: () => closeModal(),
        },
        '取消',
      ),
      el('button', { type: 'submit', class: 'btn btn-primary btn-sm' }, '保存配置'),
    ),
  );

  const titleDomain = (c.domains && c.domains[0]) || c.id.slice(0, 8);
  showModal(`编辑证书配置 · ${titleDomain}`, form);
  remarkInput.focus();
}

export async function loadCertificates() {
  syncCertRoleUI();
  populateCertAccountSelectors();
  try {
    const data = await api('/api/certificates');
    state.certs = data.certificates || [];
    renderCertStats();
    renderCertificates();
  } catch (err) {
    notify(err.message, true);
  }
}

export function initCerts() {
  on('accounts:changed', () => {
    syncCertRoleUI();
    populateCertAccountSelectors();
    renderQuickZones();
  });

  $$('[data-cert-mode]').forEach((btn) => {
    btn.addEventListener('click', () => {
      $$('[data-cert-mode]').forEach((b) => b.classList.toggle('active', b === btn));
      const mode = btn.dataset.certMode;
      const issueForm = $('#issue-form');
      const uploadForm = $('#upload-form');
      if (issueForm) issueForm.hidden = mode !== 'acme';
      if (uploadForm) uploadForm.hidden = mode !== 'upload';
    });
  });

  $('#refresh-certs')?.addEventListener('click', () => loadCertificates());
  $('#cert-search')?.addEventListener('input', () => renderCertificates());
  $('#cert-status-filter')?.addEventListener('change', () => renderCertificates());
  $('#cert-account-filter')?.addEventListener('change', () => renderCertificates());

  $('#load-zones-btn')?.addEventListener('click', async () => {
    try {
      notify('正在同步全部阿里云账户的托管域名…');
      const res = await api('/api/accounts/sync-all', { method: 'POST', body: {} });
      if (Array.isArray(res.accounts)) {
        state.accounts = res.accounts;
      } else {
        const acctData = await api('/api/accounts');
        state.accounts = acctData.accounts || [];
      }
      emit('accounts:changed', { source: 'certs' });
      emit('audit:changed');
      notify('全部账户托管域名已同步');
    } catch (err) {
      notify(err.message, true);
    }
  });

  $('#issue-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    const domains = ($('#issue-domains')?.value || '')
      .split(/[\n,\s]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    try {
      const res = await api('/api/certificates', {
        method: 'POST',
        body: {
          domains,
          account_id: $('#issue-account')?.value || '',
          key_type: $('#issue-key-type')?.value || 'EC256',
          remark: ($('#issue-remark')?.value || '').trim(),
          staging: Boolean($('#issue-staging')?.checked),
          auto_renew: Boolean($('#issue-autorenew')?.checked),
          accept_terms: Boolean($('#issue-tos')?.checked),
        },
      });
      if ($('#issue-domains')) $('#issue-domains').value = '';
      if ($('#issue-remark')) $('#issue-remark').value = '';
      notify('证书签发任务已加入队列');
      await loadCertificates();
      emit('certs:changed', { loaded: true });
      emit('audit:changed');
      if (res.job_id) emit('job:open', res.job_id);
    } catch (err) {
      notify(err.message, true);
    }
  });

  $('#upload-form')?.addEventListener('submit', async (e) => {
    e.preventDefault();
    try {
      await api('/api/certificates/upload', {
        method: 'POST',
        body: {
          fullchain_pem: $('#upload-fullchain')?.value || '',
          privkey_pem: $('#upload-privkey')?.value || '',
          remark: ($('#upload-remark')?.value || '').trim(),
        },
      });
      if ($('#upload-fullchain')) $('#upload-fullchain').value = '';
      if ($('#upload-privkey')) $('#upload-privkey').value = '';
      if ($('#upload-remark')) $('#upload-remark').value = '';
      notify('证书校验通过并已成功导入');
      await loadCertificates();
      emit('certs:changed', { loaded: true });
      emit('audit:changed');
    } catch (err) {
      notify(err.message, true);
    }
  });
}
