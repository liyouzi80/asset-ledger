// Asset Ledger API Worker
import { onRequest as metaHandler } from './meta.js';
import { onRequest as vaultHandler } from './vault.js';
import { onRequest as bgHandler } from './bg.js';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/api/meta') return metaHandler({ request, env, ctx });
    if (url.pathname === '/api/vault') return vaultHandler({ request, env, ctx });
    if (url.pathname === '/api/bg') return bgHandler({ request, env, ctx });
    return new Response('Not found', { status: 404 });
  }
};
