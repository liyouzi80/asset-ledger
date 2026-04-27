// /api/bg — 代理 Bing 每日壁纸，返回图片 URL
// 浏览器端通过此接口获取壁纸，避免跨域问题

const BING_URL = 'https://www.bing.com';
const ARCHIVE_URL = BING_URL + '/HPImageArchive.aspx?format=js&idx=0&n=1&mkt=zh-CN';

export async function onRequest(context) {
  const { request } = context;

  if (request.method === 'OPTIONS') {
    return new Response(null, {
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
      },
    });
  }

  const headers = {
    'Content-Type': 'application/json',
    'Cache-Control': 'public, max-age=3600',  // 壁纸每小时刷新一次即可
  };

  if (request.method === 'GET') {
    try {
      const resp = await fetch(ARCHIVE_URL);
      if (!resp.ok) throw new Error('Bing API returned ' + resp.status);
      const data = await resp.json();
      const img = data.images && data.images[0];
      if (!img || !img.url) throw new Error('No image data');
      const url = BING_URL + img.url;
      return new Response(JSON.stringify({ url }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 502, headers });
    }
  }

  return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405, headers });
}
