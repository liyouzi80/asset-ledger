// /api/meta — 加密元信息（salt + verifier）
// 注意：所有数据在浏览器加密后才传过来，这里看到的全是密文

export async function onRequest(context) {
  const { request, env } = context;

  // CORS（同源不需要，但放着以防你以后跨域调试）
  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    });
  }

  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
    'CDN-Cache-Control': 'no-store',
    'Cloudflare-CDN-Cache-Control': 'no-store',
    'Pragma': 'no-cache',
  };

  if (request.method === 'GET') {
    const row = await env.DB.prepare('SELECT * FROM meta WHERE id = ?').bind('main').first();
    if (!row) return new Response(JSON.stringify({ exists: false }), { headers });
    return new Response(JSON.stringify({
      exists: true,
      salt: row.salt,
      verifier: JSON.parse(row.verifier),
    }), { headers });
  }

  if (request.method === 'POST') {
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
