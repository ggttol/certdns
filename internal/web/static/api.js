import { state } from './state.js';

let unauthorizedHandler = null;

export function onUnauthorized(fn) {
  unauthorizedHandler = typeof fn === 'function' ? fn : null;
}

export async function api(path, options = {}) {
  const method = (options.method || 'GET').toUpperCase();
  const headers = {
    ...(options.headers || {}),
    'X-Requested-With': 'certdns',
  };
  if (state.csrf && method !== 'GET' && method !== 'HEAD') {
    headers['X-CSRF-Token'] = state.csrf;
  }

  let body = options.body;
  if (
    body !== undefined &&
    body !== null &&
    typeof body === 'object' &&
    !(body instanceof FormData) &&
    !(body instanceof Blob)
  ) {
    headers['Content-Type'] = 'application/json';
    body = JSON.stringify(body);
  }

  const resp = await fetch(path, {
    method,
    headers,
    body,
    credentials: 'same-origin',
  });

  if (resp.status === 413) {
    throw new Error('上传内容过大（超过 256 KB 上限）');
  }

  let data = {};
  try {
    data = await resp.json();
  } catch (_) {
    data = {};
  }

  if (resp.status === 401 && path !== '/api/login' && path !== '/api/session') {
    if (unauthorizedHandler) unauthorizedHandler();
    throw new Error(data.error || '会话已过期，请重新登录');
  }

  if (!resp.ok) {
    throw new Error(data.error || `请求失败 (${resp.status})`);
  }

  return data;
}
