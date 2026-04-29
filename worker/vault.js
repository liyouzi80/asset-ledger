// /api/vault — 加密的账本数据
// payload 是浏览器端 AES-GCM 加密的 { iv, cipher }，服务端无法解密

import { addCorsHeaders, handleOptions, checkBodySize, noCacheHeaders } from './shared.js';

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') return handleOptions(request);

  const headers = noCacheHeaders();
  addCorsHeaders(request, headers);

  if (request.method === 'GET') {
    const row = await env.DB.prepare('SELECT * FROM vault WHERE id = ?').bind('main').first();
    if (!row) return new Response(JSON.stringify({ exists: false }), { headers });
    return new Response(JSON.stringify({
      exists: true,
      payload: JSON.parse(row.payload),
      updated_at: row.updated_at,
    }), { headers });
  }

  if (request.method === 'DELETE') {
    await env.DB.prepare('DELETE FROM vault WHERE id = ?').bind('main').run();
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  if (request.method === 'POST') {
    const tooLarge = await checkBodySize(request);
    if (tooLarge) return tooLarge;

    const body = await request.json();
    const { payload } = body || {};
    if (!payload) {
      return new Response(JSON.stringify({ error: '缺少 payload' }), { status: 400, headers });
    }
    const now = Date.now();
    await env.DB.prepare(
      'INSERT INTO vault (id, payload, updated_at) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload, updated_at=excluded.updated_at'
    ).bind('main', JSON.stringify(payload), now).run();
    return new Response(JSON.stringify({ ok: true, updated_at: now }), { headers });
  }

  return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers });
}
