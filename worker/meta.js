// /api/meta — 加密元信息（salt + verifier）
// 注意：所有数据在浏览器加密后才传过来，这里看到的全是密文

import { addCorsHeaders, handleOptions, checkBodySize, noCacheHeaders } from './shared.js';

export async function onRequest(context) {
  const { request, env } = context;

  if (request.method === 'OPTIONS') return handleOptions(request);

  const headers = noCacheHeaders();
  addCorsHeaders(request, headers);

  if (request.method === 'GET') {
    const row = await env.DB.prepare('SELECT * FROM meta WHERE id = ?').bind('main').first();
    if (!row) return new Response(JSON.stringify({ exists: false }), { headers });
    return new Response(JSON.stringify({
      exists: true,
      salt: row.salt,
      verifier: JSON.parse(row.verifier),
    }), { headers });
  }

  if (request.method === 'DELETE') {
    await env.DB.prepare('DELETE FROM meta WHERE id = ?').bind('main').run();
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  if (request.method === 'POST') {
    const tooLarge = await checkBodySize(request);
    if (tooLarge) return tooLarge;

    const body = await request.json();
    const { salt, verifier } = body || {};
    if (!salt || !verifier) {
      return new Response(JSON.stringify({ error: '缺少参数' }), { status: 400, headers });
    }
    await env.DB.prepare(
      'INSERT INTO meta (id, salt, verifier) VALUES (?, ?, ?) ON CONFLICT(id) DO UPDATE SET salt=excluded.salt, verifier=excluded.verifier'
    ).bind('main', salt, JSON.stringify(verifier)).run();
    return new Response(JSON.stringify({ ok: true }), { headers });
  }

  return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers });
}
