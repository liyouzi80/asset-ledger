// Shared helpers for Worker API handlers

// Allowed origins — set via env var or default to same-origin.
// Comma-separated string, e.g. "https://example.com,https://app.example.com"
const ALLOWED_ORIGINS = (typeof ALLOWED_CORS_ORIGINS !== 'undefined')
  ? ALLOWED_CORS_ORIGINS.split(',').map(s => s.trim())
  : []; // empty = allow any origin that sent an Origin header (same-origin + debug tooling)

const MAX_BODY_BYTES = 512 * 1024; // 512 KB

function getAllowedOrigin(request) {
  const origin = request.headers.get('Origin');
  if (!origin) return null; // same-origin request — no CORS needed in response
  if (ALLOWED_ORIGINS.length === 0) return origin;
  return ALLOWED_ORIGINS.includes(origin) ? origin : null;
}

export function addCorsHeaders(request, headers) {
  const allowed = getAllowedOrigin(request);
  if (allowed) {
    headers['Access-Control-Allow-Origin'] = allowed;
    headers['Vary'] = 'Origin';
  }
  headers['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS';
  headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
  headers['Access-Control-Max-Age'] = '86400';
}

export function handleOptions(request) {
  const allowed = getAllowedOrigin(request);
  const hs = {};
  if (allowed) hs['Access-Control-Allow-Origin'] = allowed;
  hs['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS';
  hs['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
  hs['Access-Control-Max-Age'] = '86400';
  return new Response(null, { status: 204, headers: hs });
}

export async function checkBodySize(request) {
  const contentLength = request.headers.get('Content-Length');
  if (contentLength && parseInt(contentLength) > MAX_BODY_BYTES) {
    return new Response(JSON.stringify({ error: '请求体过大' }), { status: 413 });
  }
  return null;
}

export function noCacheHeaders() {
  return {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'CDN-Cache-Control': 'no-store',
    'Cloudflare-CDN-Cache-Control': 'no-store',
    'Pragma': 'no-cache',
  };
}

// ============================================================
// 写保护 — TOFU 令牌
// 客户端在加密 vault 内携带一个随机令牌（服务端永远看不到明文 vault），
// 写操作通过 Authorization: Bearer 出示。服务端只存 SHA-256 哈希
// （meta 表 id='_auth' 行，salt 列），首个携带令牌的写入完成绑定。
// 读操作不受影响：密文本身由 AES-GCM 保护。
// ============================================================
async function sha256Hex(text) {
  const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
  return [...new Uint8Array(buf)].map(b => b.toString(16).padStart(2, '0')).join('');
}

function bearerToken(request) {
  const auth = request.headers.get('Authorization') || '';
  return auth.startsWith('Bearer ') ? auth.slice(7).trim() : null;
}

// 返回 null = 放行；返回字符串 = 拒绝原因（调用方构造 401）
// bindOnFirst=true 时（仅 POST），未绑定状态下携带令牌的首次写入完成 TOFU 绑定；
// DELETE 不绑定，避免重置流程把刚清除的令牌又写回来。
export async function checkWriteAuth(request, env, bindOnFirst = false) {
  const token = bearerToken(request);
  const row = await env.DB.prepare("SELECT salt FROM meta WHERE id = '_auth'").first();
  if (row && row.salt) {
    if (!token) return '缺少写入令牌';
    if ((await sha256Hex(token)) !== row.salt) return '写入令牌无效';
    return null;
  }
  // 尚未绑定：携带令牌的首次写入即完成绑定（TOFU）
  if (bindOnFirst && token) {
    await env.DB.prepare(
      "INSERT INTO meta (id, salt, verifier) VALUES ('_auth', ?, '{}') ON CONFLICT(id) DO UPDATE SET salt=excluded.salt"
    ).bind(await sha256Hex(token)).run();
  }
  return null;
}

// 重置时解除绑定（仅在已通过 checkWriteAuth 后调用）
export async function clearWriteAuth(env) {
  await env.DB.prepare("DELETE FROM meta WHERE id = '_auth'").run();
}
