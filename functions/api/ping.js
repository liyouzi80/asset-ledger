// /api/ping — 健康检查，前端启动时用来判断后端是否可用

export async function onRequest(context) {
  return new Response(JSON.stringify({ ok: true, ts: Date.now() }), {
    headers: {
      'Content-Type': 'application/json',
      'Cache-Control': 'no-store',
    },
  });
}
