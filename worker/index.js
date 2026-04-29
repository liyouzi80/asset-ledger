// Asset Ledger API Worker
import { onRequest as metaHandler } from './meta.js';
import { onRequest as vaultHandler } from './vault.js';
import { onRequest as pingHandler } from './ping.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/meta') return metaHandler({ request, env, ctx });
    if (url.pathname === '/api/vault') return vaultHandler({ request, env, ctx });
    if (url.pathname === '/api/ping') return pingHandler({ request, env, ctx });
    // 其他路径由 [assets] 处理（静态文件）
    return new Response('Not found', { status: 404 });
  }
};
