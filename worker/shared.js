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
  headers['Access-Control-Allow-Headers'] = 'Content-Type';
  headers['Access-Control-Max-Age'] = '86400';
}

export function handleOptions(request) {
  const allowed = getAllowedOrigin(request);
  const hs = {};
  if (allowed) hs['Access-Control-Allow-Origin'] = allowed;
  hs['Access-Control-Allow-Methods'] = 'GET, POST, DELETE, OPTIONS';
  hs['Access-Control-Allow-Headers'] = 'Content-Type';
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
