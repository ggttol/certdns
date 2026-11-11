import { state, on, emit } from './state.js';
import { api } from './api.js';
import { $, el, showModal, fmtTime, statusBadge } from './ui.js';

function updateJobBadge() {
  const activeCount = state.jobs.filter(
    (j) => j.status === 'queued' || j.status === 'running',
  ).length;
  const badge = $('#nav-job-badge');
  if (badge) {
    badge.textContent = String(activeCount);
    badge.hidden = activeCount === 0;
  }
}

function renderJobs() {
  const wrap = $('#jobs-list');
  if (!wrap) return;
  wrap.replaceChildren();

  if (state.jobs.length === 0) {
    wrap.append(el('div', { class: 'empty-cell' }, '暂无签发或续期任务记录。'));
    return;
  }

  const certMap = new Map(
    state.certs.map((c) => [c.id, (c.domains || []).join(', ')]),
  );

  for (const j of state.jobs) {
    const domains = certMap.get(j.certificate_id) || j.certificate_id.slice(0, 8);
    const kindLabel = j.kind === 'issue' ? '首次签发' : '证书续期';
    const trigLabel = j.trigger === 'auto' ? '自动调度' : '手动触发';

    wrap.append(
      el(
        'div',
        { class: 'job-row' },
        el(
          'div',
          {},
          el('strong', {}, `${kindLabel} · ${domains}`),
          el('div', { class: 'muted small' }, `${trigLabel} · 创建于 ${fmtTime(j.created_at)}`),
        ),
        el(
          'div',
          { class: 'btn-row' },
          statusBadge(j.status),
          el(
            'button',
            {
              type: 'button',
              class: 'btn btn-secondary btn-sm',
              onclick: () => openJobModal(j.id),
            },
            '查看日志',
          ),
        ),
      ),
    );
  }
}

export async function loadJobs() {
  try {
    const data = await api('/api/jobs');
    state.jobs = data.jobs || [];
    updateJobBadge();
    renderJobs();
  } catch (_) {}
}

export async function openJobModal(jobId) {
  if (!jobId) return;
  let closed = false;
  let inFlight = false;
  let timer = null;

  const stopPolling = () => {
    closed = true;
    clearInterval(timer);
    timer = null;
  };

  const pre = el('pre', { class: 'log-pre' }, '正在读取任务输出…');
  showModal(`任务日志 #${jobId.slice(0, 8)}`, pre, {
    onClose: stopPolling,
  });

  async function refresh() {
    if (closed || inFlight) return;
    inFlight = true;
    try {
      const j = await api(`/api/jobs/${jobId}`);
      if (closed) return;
      pre.textContent =
        j.output ||
        (j.status === 'queued'
          ? '任务排队中，等待后台 Worker 执行…'
          : '正在初始化 ACME 客户端…');
      pre.scrollTop = pre.scrollHeight;
      if (j.status !== 'queued' && j.status !== 'running') {
        stopPolling();
        await loadJobs();
        emit('certs:changed');
      }
    } catch (err) {
      if (closed) return;
      pre.textContent = err.message;
      stopPolling();
    } finally {
      inFlight = false;
    }
  }

  await refresh();
  if (!closed) {
    timer = setInterval(refresh, 2000);
  }
}

export function initJobs() {
  $('#refresh-jobs')?.addEventListener('click', () => loadJobs());
  on('job:open', (id) => openJobModal(id));
  on('certs:changed', () => renderJobs());
}
