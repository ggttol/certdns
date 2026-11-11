export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

const BOOL_ATTRS = new Set([
  'checked',
  'disabled',
  'hidden',
  'readonly',
  'readOnly',
  'required',
  'selected',
  'multiple',
  'autofocus',
]);

export function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  if (attrs && typeof attrs === 'object') {
    for (const [k, v] of Object.entries(attrs)) {
      if (k === 'style') {
        throw new Error('CSP: inline style forbidden');
      }
      if (BOOL_ATTRS.has(k)) {
        const prop = k === 'readonly' ? 'readOnly' : k;
        const flag = Boolean(v);
        if (prop in node) node[prop] = flag;
        if (flag) node.setAttribute(k.toLowerCase(), '');
        continue;
      }
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class' || k === 'className') {
        node.className = String(v);
      } else if (k === 'dataset' && typeof v === 'object') {
        Object.assign(node.dataset, v);
      } else if (k.startsWith('on') && typeof v === 'function') {
        node.addEventListener(k.slice(2).toLowerCase(), v);
      } else if (v === true) {
        node.setAttribute(k, '');
      } else {
        node.setAttribute(k, String(v));
      }
    }
  }
  for (const child of children.flat(Infinity)) {
    if (child === null || child === undefined || child === false) continue;
    node.append(child instanceof Node ? child : document.createTextNode(String(child)));
  }
  return node;
}

let toastTimer = null;

export function notify(msg, isError = false) {
  const box = $('#toast');
  if (!box) return;
  box.textContent = msg;
  box.className = isError ? 'toast error' : 'toast';
  box.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => {
    box.hidden = true;
  }, 4500);
}

let modalOnClose = null;
let modalBound = false;

function runModalCleanup() {
  if (typeof modalOnClose === 'function') {
    const fn = modalOnClose;
    modalOnClose = null;
    try {
      fn();
    } catch (_) {}
  } else {
    modalOnClose = null;
  }
}

function ensureModalBindings() {
  if (modalBound) return;
  const backdrop = $('#modal-backdrop');
  const closeBtn = $('#modal-close');
  if (!backdrop || !closeBtn) return;
  modalBound = true;

  closeBtn.addEventListener('click', () => closeModal());
  backdrop.addEventListener('click', (e) => {
    if (e.target === backdrop) closeModal();
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !backdrop.hidden) {
      closeModal();
    }
  });
}

if (typeof document !== 'undefined' && document.readyState !== 'loading') {
  ensureModalBindings();
} else if (typeof document !== 'undefined') {
  document.addEventListener('DOMContentLoaded', ensureModalBindings, { once: true });
}

export function showModal(title, node, { onClose } = {}) {
  ensureModalBindings();
  runModalCleanup();
  modalOnClose = typeof onClose === 'function' ? onClose : null;

  const titleEl = $('#modal-title');
  const bodyEl = $('#modal-body');
  const backdrop = $('#modal-backdrop');
  if (titleEl) titleEl.textContent = title || '';
  if (bodyEl) {
    if (node instanceof Node) {
      bodyEl.replaceChildren(node);
    } else if (Array.isArray(node)) {
      bodyEl.replaceChildren(...node.filter(Boolean));
    } else if (node !== null && node !== undefined) {
      bodyEl.replaceChildren(document.createTextNode(String(node)));
    } else {
      bodyEl.replaceChildren();
    }
  }
  if (backdrop) backdrop.hidden = false;
}

export function closeModal() {
  runModalCleanup();
  const backdrop = $('#modal-backdrop');
  const bodyEl = $('#modal-body');
  if (backdrop) backdrop.hidden = true;
  if (bodyEl) bodyEl.replaceChildren();
}

export async function copyText(text, label = '内容') {
  try {
    await navigator.clipboard.writeText(String(text ?? ''));
    notify(`已复制${label}到剪贴板`);
  } catch (_) {
    notify('复制失败，请手动选择复制', true);
  }
}

export function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString('zh-CN', { hour12: false });
}

export function statusBadge(status, daysLeft) {
  if (status === 'expired' || (status === 'valid' && typeof daysLeft === 'number' && daysLeft < 0)) {
    const label = typeof daysLeft === 'number' ? `已过期 (${Math.abs(daysLeft)} 天)` : '已过期';
    return el('span', { class: 'badge badge-danger' }, label);
  }
  if (status === 'valid') {
    if (typeof daysLeft === 'number' && daysLeft >= 0 && daysLeft <= 30) {
      return el('span', { class: 'badge badge-warn' }, `即将到期 (${daysLeft} 天)`);
    }
    return el(
      'span',
      { class: 'badge badge-success' },
      typeof daysLeft === 'number' ? `有效 (${daysLeft} 天)` : '有效',
    );
  }
  const map = {
    queued: ['排队中', 'badge-info'],
    issuing: ['签发中…', 'badge-info'],
    renewing: ['续期中…', 'badge-info'],
    running: ['执行中…', 'badge-info'],
    succeeded: ['已完成', 'badge-success'],
    error: ['异常', 'badge-danger'],
    failed: ['失败', 'badge-danger'],
  };
  const [label, cls] = map[status] || [status || '未知', ''];
  return el('span', { class: cls ? `badge ${cls}` : 'badge' }, label);
}

export function roleBadge(role) {
  if (role === 'admin') return el('span', { class: 'badge badge-info' }, '系统管理员 (admin)');
  if (role === 'operator') return el('span', { class: 'badge badge-blue' }, '运维操作员 (operator)');
  return el('span', { class: 'badge' }, '只读审计员 (viewer)');
}

export function editionLabel(ed) {
  if (ed === 'intl') return '国际站 INTL';
  if (ed === 'custom') return '自定义站点';
  return '中国站 CN';
}
