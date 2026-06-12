'use strict';

// 字体栈 — 与 css/variables.css 保持一致（系统字体，无外部下载）
const UI_FONT = "-apple-system, BlinkMacSystemFont, 'SF Pro Text', 'Helvetica Neue', 'PingFang SC', 'Microsoft YaHei', sans-serif";
const MONO_FONT = "'SF Mono', ui-monospace, 'Menlo', 'Consolas', monospace";

// ============================================================
// 加密层 · Web Crypto + WebAuthn PRF
// ============================================================
const CRYPTO_CONFIG = {
  saltLen: 16,
  ivLen: 12,
  iterations: 250000,
  hash: 'SHA-256',
  keyLen: 256,
};

// PRF 用的固定 salt（每个用户首次注册时生成并保存）
function randomBytes(len) { return crypto.getRandomValues(new Uint8Array(len)); }
function bufToB64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  return btoa(s);
}
function b64ToBuf(b64) {
  const s = atob(b64);
  const bytes = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) bytes[i] = s.charCodeAt(i);
  return bytes;
}

async function deriveKeyFromPassword(password, salt) {
  const enc = new TextEncoder();
  const baseKey = await crypto.subtle.importKey(
    'raw', enc.encode(password), { name: 'PBKDF2' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: CRYPTO_CONFIG.iterations, hash: CRYPTO_CONFIG.hash },
    baseKey,
    { name: 'AES-GCM', length: CRYPTO_CONFIG.keyLen },
    true,  // extractable，便于"密码 → 主密钥"和"PRF → 主密钥"两条路径都能加密同一份数据
    ['encrypt', 'decrypt']
  );
}

async function deriveKeyFromPRF(prfOutput) {
  // PRF 输出是 32 字节，用 HKDF 派生 AES key
  const baseKey = await crypto.subtle.importKey(
    'raw', prfOutput, { name: 'HKDF' }, false, ['deriveKey']
  );
  return crypto.subtle.deriveKey(
    { name: 'HKDF', salt: new Uint8Array(0), info: new TextEncoder().encode('asset-ledger-aes-key'), hash: 'SHA-256' },
    baseKey,
    { name: 'AES-GCM', length: CRYPTO_CONFIG.keyLen },
    true,
    ['encrypt', 'decrypt']
  );
}

async function exportRawKey(key) {
  return new Uint8Array(await crypto.subtle.exportKey('raw', key));
}
async function importRawKey(raw) {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM' }, true, ['encrypt', 'decrypt']);
}

async function encryptJSON(obj, key) {
  const iv = randomBytes(CRYPTO_CONFIG.ivLen);
  const cipher = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv }, key, new TextEncoder().encode(JSON.stringify(obj))
  );
  return { iv: bufToB64(iv), cipher: bufToB64(cipher) };
}
async function decryptJSON(payload, key) {
  const iv = b64ToBuf(payload.iv);
  const cipher = b64ToBuf(payload.cipher);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipher);
  return JSON.parse(new TextDecoder().decode(plain));
}

// ============ Passkey ============
function isPRFSupported() {
  return !!(window.PublicKeyCredential && navigator.credentials);
}

async function registerPasskey() {
  // 创建一个 Passkey，启用 PRF 扩展
  const userId = randomBytes(16);
  const challenge = randomBytes(32);
  const credential = await navigator.credentials.create({
    publicKey: {
      challenge,
      rp: { name: '资产账本' },
      user: { id: userId, name: 'asset-ledger-user', displayName: '账本用户' },
      pubKeyCredParams: [
        { alg: -7, type: 'public-key' },   // ES256
        { alg: -257, type: 'public-key' }, // RS256
      ],
      authenticatorSelection: {
        residentKey: 'required',
        userVerification: 'required',
      },
      timeout: 60000,
      extensions: {
        prf: {
          eval: { first: new TextEncoder().encode('asset-ledger-prf-salt-v1') },
        },
      },
    },
  });
  if (!credential) throw new Error('用户取消');

  const ext = credential.getClientExtensionResults();
  if (!ext.prf || !ext.prf.enabled) {
    throw new Error('此设备/浏览器不支持 PRF 扩展（需要 Safari 18+ / Chrome 132+ / 较新的 Authenticator）');
  }

  // 注册时部分浏览器返回 results.first，部分不返回 — 都接受，没有就立刻做一次 get 拿
  let prfOutput = ext.prf.results && ext.prf.results.first;
  if (!prfOutput) {
    const credId = new Uint8Array(credential.rawId);
    prfOutput = await getPasskeyPRF(credId);
  }

  return {
    credentialId: bufToB64(credential.rawId),
    prfOutput: new Uint8Array(prfOutput),
  };
}

async function getPasskeyPRF(credentialIdBuf) {
  const challenge = randomBytes(32);
  const assertion = await navigator.credentials.get({
    publicKey: {
      challenge,
      allowCredentials: [{
        id: credentialIdBuf,
        type: 'public-key',
      }],
      userVerification: 'required',
      timeout: 60000,
      extensions: {
        prf: {
          eval: { first: new TextEncoder().encode('asset-ledger-prf-salt-v1') },
        },
      },
    },
  });
  if (!assertion) throw new Error('用户取消');
  const ext = assertion.getClientExtensionResults();
  if (!ext.prf || !ext.prf.results || !ext.prf.results.first) {
    throw new Error('PRF 未返回结果');
  }
  return new Uint8Array(ext.prf.results.first);
}

// ============================================================
// 存储层 · Cloudflare D1 API
// meta:    { id:'main', salt, verifier?, kdf:'pbkdf2'|'none',
//            wrappedKeyByPassword?, wrappedKeyByPasskey?, passkeyCredId? }
// vault:   { id:'main', payload }
// ============================================================
// API 基址：默认走同源（部署到 Pages 后是 /api/*）
const API_BASE = location.hostname === 'localhost' ? 'http://localhost:8787' : '';

// 写保护令牌：首次生成后藏进加密 vault 随密文同步；服务端只存哈希。
// 新设备解锁 → 解密 vault → 自动拿到令牌，无需任何手动配置。
function ensureApiToken() {
  if (!state.apiToken) {
    state.apiToken = bufToB64(crypto.getRandomValues(new Uint8Array(32)));
  }
  return state.apiToken;
}

async function apiGet(path) {
  // 加时间戳避免任何中间缓存
  const sep = path.includes('?') ? '&' : '?';
  const url = API_BASE + path + sep + '_t=' + Date.now();
  const r = await fetch(url, { cache: 'no-store' });
  if (!r.ok) throw new Error('API ' + path + ' 失败: ' + r.status);
  return r.json();
}
async function apiPost(path, body) {
  const headers = { 'Content-Type': 'application/json' };
  if (state.apiToken) headers['Authorization'] = 'Bearer ' + state.apiToken;
  const r = await fetch(API_BASE + path, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
    cache: 'no-store',
  });
  if (!r.ok) {
    let msg = 'API ' + path + ' 失败: ' + r.status;
    try { const e = await r.json(); if (e.error) msg += ' · ' + e.error; } catch {}
    throw new Error(msg);
  }
  return r.json();
}

// 上层兼容接口：保持 dbGet/dbPut 签名不变
// meta 对象除了 salt/verifier，还可能有 wrappedKeyByPassword/wrappedKeyByPasskey/passkeyCredId/kdf
// 服务端把这些扩展字段统一存进 verifier 的 _extra 里
async function apiDelete(path) {
  const headers = state.apiToken ? { 'Authorization': 'Bearer ' + state.apiToken } : {};
  const r = await fetch(API_BASE + path, { method: 'DELETE', headers, cache: 'no-store' });
  if (!r.ok) throw new Error('API ' + path + ' 删除失败: ' + r.status);
  return r.json();
}

async function dbGet(store) {
  if (store === 'meta') {
    const r = await apiGet('/api/meta');
    if (!r.exists) return undefined;
    const { _extra, ...verifier } = r.verifier || {};
    return { id: 'main', salt: r.salt, verifier, ...(_extra || {}) };
  }
  if (store === 'vault') {
    const r = await apiGet('/api/vault');
    if (!r.exists) return undefined;
    state.lastKnownUpdatedAt = r.updated_at || 0;
    return { id: 'main', payload: r.payload };
  }
}

async function dbPut(store, obj) {
  if (store === 'meta') {
    const { id, salt, verifier, ...extras } = obj;
    const wrappedVerifier = { ...verifier, _extra: extras };
    return apiPost('/api/meta', { salt, verifier: wrappedVerifier });
  }
  if (store === 'vault') {
    return apiPost('/api/vault', { payload: obj.payload });
  }
}

async function dbClearAll() {
  await apiDelete('/api/meta');
  await apiDelete('/api/vault');
  state.apiToken = null;
  clearLocalMirror();
}


// ============================================================
// localStorage 主密钥缓存 — 免锁屏自动解锁
// ============================================================
const LOCAL_KEY_STORAGE = 'asset-ledger-key-v1';

async function cacheMasterKeyLocally(masterKey) {
  try {
    const raw = await crypto.subtle.exportKey('raw', masterKey);
    localStorage.setItem(LOCAL_KEY_STORAGE, bufToB64(new Uint8Array(raw)));
  } catch { /* 静默降级 */ }
}

async function loadCachedMasterKey() {
  try {
    const b64 = localStorage.getItem(LOCAL_KEY_STORAGE);
    if (!b64) return null;
    const raw = b64ToBuf(b64);
    return await crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
  } catch {
    localStorage.removeItem(LOCAL_KEY_STORAGE);
    return null;
  }
}

// ============================================================
// 本地镜像 · 防止云端被错误覆盖
// 每次成功解锁后，把 vault 加密 payload 存一份到 localStorage
// 只保留最近 1 份（更早的版本已经无意义，因为没有对应密钥）
// 镜像内容仍是加密的，只有当前 masterKey 能解
// ============================================================
const MIRROR_KEY = 'asset-ledger-local-mirror-v1';

function writeLocalMirror(metaObj, vaultPayload) {
  try {
    localStorage.setItem(MIRROR_KEY, JSON.stringify({
      ts: Date.now(),
      meta: metaObj,         // 包含 salt/verifier/wrappedKey 等所有解锁所需信息
      payload: vaultPayload, // 加密的 vault payload
    }));
  } catch (e) {
    console.warn('本地镜像写入失败', e);
  }
}

function readLocalMirror() {
  try {
    const raw = localStorage.getItem(MIRROR_KEY);
    if (!raw) return null;
    const obj = JSON.parse(raw);
    // 简单校验
    if (!obj || !obj.meta || !obj.payload) return null;
    return obj;
  } catch (e) {
    return null;
  }
}

function clearLocalMirror() {
  try { localStorage.removeItem(MIRROR_KEY); } catch {}
}

// 给用户一个"从本地镜像恢复"的入口
async function offerLocalRestore(mirror) {
  const ageHours = ((Date.now() - mirror.ts) / 3600000).toFixed(1);
  const ok = confirm(
    `检测到本地保存的备份镜像。\n\n` +
    `备份时间：${new Date(mirror.ts).toLocaleString('zh-CN')}（${ageHours} 小时前）\n\n` +
    `点击"确定"会用此备份恢复云端数据。注意：解锁仍需要原 Passkey 或密码。\n\n` +
    `继续？`
  );
  if (!ok) return;
  try {
    // 把镜像写回 D1
    const { _extra, ...verifier } = mirror.meta.verifier || {};
    await apiPost('/api/meta', { salt: mirror.meta.salt, verifier: { ...verifier, _extra: _extra || {} } });
    await apiPost('/api/vault', { payload: mirror.payload });
    showToast('已从本地镜像恢复，请重新解锁');
    setTimeout(() => location.reload(), 1500);
  } catch (e) {
    showToast('恢复失败：' + (e.message || e), 'error');
  }
}

// ============================================================
// 默认数据
// ============================================================
const DEFAULT_GROUP_ORDER = ['美股券商', '港股 / 港币账户', 'A 股券商', '大陆银行', '移动支付', '信用卡', '其他资产'];
const DEFAULT_ACCOUNTS = [
  { group: '美股券商', name: '美股账户 1', type: 'asset', tag: 'investment' },
  { group: '美股券商', name: '美股账户 2', type: 'asset', tag: 'investment' },
  { group: '美股券商', name: '美股账户 3', type: 'asset', tag: 'investment' },
  { group: '美股券商', name: '美股账户 4', type: 'asset', tag: 'investment' },
  { group: '港股 / 港币账户', name: '香港银行 1', type: 'asset', tag: 'investment' },
  { group: '港股 / 港币账户', name: '香港银行 2', type: 'asset', tag: 'investment' },
  { group: '港股 / 港币账户', name: '香港银行 3', type: 'asset', tag: 'investment' },
  { group: 'A 股券商', name: 'A 股账户 1', type: 'asset', tag: 'investment' },
  { group: 'A 股券商', name: 'A 股账户 2', type: 'asset', tag: 'investment' },
  { group: 'A 股券商', name: 'A 股账户 3', type: 'asset', tag: 'investment' },
  { group: '大陆银行', name: '大陆银行 1', type: 'asset', tag: 'cash' },
  { group: '移动支付', name: '支付宝', type: 'asset', tag: 'cash' },
  { group: '移动支付', name: '微信', type: 'asset', tag: 'cash' },
  { group: '信用卡', name: '大陆信用卡 1', type: 'liability', tag: 'liability' },
  { group: '信用卡', name: '大陆信用卡 2', type: 'liability', tag: 'liability' },
  { group: '其他资产', name: '其他收入', type: 'asset', tag: 'cash' },
  { group: '其他资产', name: '外部欠款（应收）', type: 'asset', tag: 'credit' },
];
function buildDefaultData() {
  let i = 1;
  const accounts = DEFAULT_ACCOUNTS.map(a => ({
    id: 'a' + Date.now() + '-' + (i++), order: i, tag: a.tag || 'cash', ...a,
  }));
  return { accounts, snapshots: [], groupOrder: [...DEFAULT_GROUP_ORDER], targetAllocation: {} };
}

// ============================================================
// 状态
// ============================================================
let state = {
  masterKey: null,        // CryptoKey: 真正的数据加密主密钥
  apiToken: null,         // 写保护令牌：随加密 vault 同步，服务端只存哈希
  unlocked: false,
  accounts: [],
  snapshots: [],
  groupOrder: [],
  current: 'dashboard',
  editingMonth: null,
  editingDraft: null,
  editAccId: null,
  editGroupOriginal: null,
  theme: 'system',
  lockMode: 'passkey',    // 当前 UI 模式：passkey | password
  lastKnownUpdatedAt: 0,  // 服务器端 vault 最新时间戳（冲突检测用）
  cachedMeta: null,       // 解锁后缓存的 meta，避免 persistVault 每次额外 fetch
  viewMode: 'all',        // 'all' | 'investment' —— 投资资产独立视图
  targetAllocation: {},   // { [groupName]: percentage } —— 目标配置占比
  anomalyThreshold: 0.2,  // 重大变化提醒阈值，默认 ±20%
  historyView: 'list',    // 'list' | 'matrix' —— 历史页视图模式
  returnPeriod: 'ytd',    // '1m' | '3m' | '6m' | 'ytd' | 'custom' —— 收益率模块默认期间
  returnIndicator: 'twr', // 'twr' | 'simple' | 'amount' —— 默认指标
  returnCustomStart: null, // 自定义期间起始 YYYY-MM
  returnCustomEnd: null,   // 自定义期间结束 YYYY-MM
};
let localBackupDirectoryHandle = null;

function migrateAccounts(accounts) {
  // 向后兼容：为旧账户补充/修正 tag 字段
  for (const a of accounts) {
    if (a.group === '其他资产' || a.group === '信用卡') {
      if (!a.tag || a.tag === 'investment') {
        if (a.name && a.name.includes('欠款')) a.tag = 'credit';
        else a.tag = 'cash';
      }
    }
    if (!a.tag) {
      if (a.type === 'liability') a.tag = 'liability';
      else if (a.group && (a.group.includes('券商') || a.group.includes('港股') || a.group.includes('A 股'))) a.tag = 'investment';
      else if (a.name && a.name.includes('欠款')) a.tag = 'credit';
      else a.tag = 'cash';
    }
  }
  return accounts;
}

// ============================================================
// 主题
// ============================================================
function applyTheme(mode) {
  state.theme = mode;
  localStorage.setItem('asset-theme', mode);
  let actual = mode;
  if (mode === 'system') {
    actual = window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  }
  document.documentElement.setAttribute('data-theme', actual);
  // 同步 iOS Safari 顶栏 / PWA 状态栏颜色
  const themeColors = { dark: '#08090a', light: '#f5f5f7', suba: '#f2f2f7' };
  document.querySelectorAll('meta[name="theme-color"]').forEach(m => {
    m.setAttribute('content', themeColors[actual] || themeColors.light);
  });
  Object.keys(cssVarCache).forEach(k => delete cssVarCache[k]);
  document.querySelectorAll('[data-theme-set]').forEach(b => {
    b.classList.toggle('active', b.dataset.themeSet === mode);
  });
  if (state.unlocked && state.current === 'dashboard') renderDashboard();
  if (state.unlocked && state.current === 'entry') renderEntry();
  if (state.unlocked && state.current === 'history') renderHistory();
}
window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => {
  if (state.theme === 'system') applyTheme('system');
});
document.querySelectorAll('[data-theme-set]').forEach(b => {
  b.addEventListener('click', () => applyTheme(b.dataset.themeSet));
});

// ============================================================
// 锁屏 / 解锁
// ============================================================
let _persistQueue = Promise.resolve();
async function persistVault() {
  await _persistQueue;
  return _persistQueue = (async () => {
  // 冲突检测：检查云端是否有更新的数据
  if (state.lastKnownUpdatedAt !== 0) {
    let userCancelled = false;
    try {
      const server = await apiGet('/api/vault');
      const serverUpdatedAt = server.exists ? (server.updated_at || 0) : 0;
      if (serverUpdatedAt !== state.lastKnownUpdatedAt) {
        const ok = confirm(
          '⚠️ 检测到数据冲突\n\n' +
          '云端数据已被其他设备修改（' + new Date(serverUpdatedAt).toLocaleString('zh-CN') + '）。\n' +
          '继续保存将覆盖其他设备上的最新数据。\n\n' +
          '点击「确定」覆盖保存\n' +
          '点击「取消」先刷新页面查看最新数据'
        );
        if (!ok) {
          userCancelled = true;
          showToast('已取消保存，请刷新页面获取最新数据', 'error');
        }
      }
    } catch (e) {
      // 冲突检测本身失败不阻止写入（可能是网络问题）
      console.warn('冲突检测失败，继续写入:', e);
    }
    if (userCancelled) return;
  }

  ensureApiToken();
  const payload = await encryptJSON({
    accounts: state.accounts,
    snapshots: state.snapshots,
    groupOrder: state.groupOrder,
    targetAllocation: state.targetAllocation,
    apiToken: state.apiToken,
  }, state.masterKey);
  await dbPut('vault', { id: 'main', payload });

  // 回读校验：D1 有最终一致性窗口，给最多 3 次重试 + 短延迟
  let verified = false;
  let lastErr = null;
  for (let attempt = 0; attempt < 3; attempt++) {
    if (attempt > 0) await new Promise(r => setTimeout(r, 300 * attempt));
    try {
      const check = await dbGet('vault');
      if (check && check.payload && check.payload.iv === payload.iv && check.payload.cipher === payload.cipher) {
        verified = true;
        break;
      }
      lastErr = '云端读到的 IV/cipher 与刚发送的不一致（attempt ' + (attempt + 1) + '）';
    } catch (e) {
      lastErr = e.message || String(e);
    }
  }
  if (!verified) {
    throw new Error('云端写入校验失败：' + lastErr);
  }

  // 同步写本地镜像（优先用缓存的 meta，避免额外网络请求）
  try {
    const meta = state.cachedMeta || await dbGet('meta');
    if (meta) writeLocalMirror(meta, payload);
  } catch (e) { /* 静默 */ }

  // 本地冷备份：每次保存静默落盘到授权目录
  if (localBackupDirectoryHandle) {
    try {
      const fileName = 'asset_ledger_' + new Date().toISOString().slice(0, 10) + '.json';
      const fileHandle = await localBackupDirectoryHandle.getFileHandle(fileName, { create: true });
      const writable = await fileHandle.createWritable();
      const backupData = JSON.stringify({
        version: 2,
        exportedAt: new Date().toISOString(),
        meta: state.cachedMeta || await dbGet('meta'),
        vault: { payload },
      });
      await writable.write(backupData);
      await writable.close();
    } catch (err) {
      console.warn('本地冷备份写入失败，可能权限过期:', err);
      localBackupDirectoryHandle = null;
      const statusEl = document.getElementById('backup-status');
      if (statusEl) statusEl.style.display = 'none';
    }
  }
  })();
}

// 用一个"包装密钥"加密"主密钥"得到 wrappedKey
async function wrapMasterKey(masterKey, wrappingKey) {
  const raw = await exportRawKey(masterKey);
  return encryptJSON({ raw: bufToB64(raw) }, wrappingKey);
}
async function unwrapMasterKey(wrapped, wrappingKey) {
  const obj = await decryptJSON(wrapped, wrappingKey);
  const raw = b64ToBuf(obj.raw);
  return importRawKey(raw);
}

async function refreshFromCloud() {
  if (state.entryDirty) {
    if (!confirm('当前录入页有未保存的修改，刷新将丢失这些改动。\n\n是否确认刷新？')) return;
  }
  try {
    const btn = document.getElementById('refresh-btn');
    if (btn) btn.style.opacity = '0.5';
    const vaultResp = await apiGet('/api/vault');
    if (!vaultResp || !vaultResp.exists || !vaultResp.payload) {
      showToast('云端无数据', 'error');
      return;
    }
    const decrypted = await decryptJSON(vaultResp.payload, state.masterKey);
    state.accounts = migrateAccounts(decrypted.accounts || []);
    state.snapshots = decrypted.snapshots || [];
    state.groupOrder = decrypted.groupOrder || [];
    state.targetAllocation = decrypted.targetAllocation || {};
    if (decrypted.apiToken) state.apiToken = decrypted.apiToken;
    state.lastKnownUpdatedAt = vaultResp.updated_at || 0;

    if (state.current === 'dashboard') renderDashboard();
    else if (state.current === 'entry') renderEntry();
    else if (state.current === 'history') renderHistory();
    showToast('已刷新云端数据');
  } catch (err) {
    showToast('刷新失败：' + (err.message || '未知错误'), 'error');
  } finally {
    const btn = document.getElementById('refresh-btn');
    if (btn) btn.style.opacity = '1';
  }
}

function setLockUI(mode, isFirstTime, hasPasskey) {
  state.lockMode = mode;
  const tabs = document.getElementById('lock-mode-tabs');
  const passkeyArea = document.getElementById('lock-passkey-area');
  const passwordArea = document.getElementById('lock-password-area');
  const confirmGroup = document.getElementById('lock-confirm-group');
  const warning = document.getElementById('lock-warning');
  const title = document.getElementById('lock-title');
  const subtitle = document.getElementById('lock-subtitle');
  const passkeyText = document.getElementById('passkey-action-text');

  if (isFirstTime) {
    // 首次设置：只能用密码
    mode = 'password';
    title.textContent = '设置主密码';
    subtitle.textContent = '设置一个用于加密所有数据的主密码（至少 6 位）';
    tabs.style.display = 'none';
    warning.style.display = '';
    confirmGroup.style.display = '';
    passkeyArea.style.display = 'none';
    passwordArea.style.display = '';
  } else if (hasPasskey) {
    // 已有 Passkey：默认 Passkey，显示切换按钮
    tabs.style.display = '';
    warning.style.display = 'none';
    confirmGroup.style.display = 'none';
    if (mode === 'passkey') {
      title.textContent = '解锁账本';
      subtitle.textContent = '使用 Touch ID / Face ID 解锁';
      passkeyText.textContent = '使用 Passkey 解锁';
      passkeyArea.style.display = '';
      passwordArea.style.display = 'none';
    } else {
      title.textContent = '输入主密码';
      subtitle.textContent = '请输入密码以解锁账本';
      passkeyArea.style.display = 'none';
      passwordArea.style.display = '';
    }
  } else {
    // 仅有密码：无切换
    title.textContent = '输入主密码';
    subtitle.textContent = '请输入密码以解锁账本';
    tabs.style.display = 'none';
    warning.style.display = 'none';
    confirmGroup.style.display = 'none';
    passkeyArea.style.display = 'none';
    passwordArea.style.display = '';
  }

  document.querySelectorAll('#lock-mode-tabs button').forEach(b => {
    b.classList.toggle('active', b.dataset.mode === mode);
  });
}



async function unlockOrInit() {
  // 先尝试从 localStorage 恢复密钥 → 直接进入
  const cached = await loadCachedMasterKey();
  if (cached) {
    state.masterKey = cached;
    try {
      const vault = await dbGet('vault');
      if (vault) {
        const data = await decryptJSON(vault.payload, state.masterKey);
        state.accounts = migrateAccounts(data.accounts || []);
        state.snapshots = data.snapshots || [];
        state.groupOrder = data.groupOrder && data.groupOrder.length ? data.groupOrder : [...DEFAULT_GROUP_ORDER];
        state.targetAllocation = data.targetAllocation || {};
        if (data.apiToken) state.apiToken = data.apiToken;
        await enterApp();
        return;
      }
    } catch (e) {
      // 网络请求失败 → 尝试本地镜像离线解锁
      console.warn('Auto-unlock via network failed, trying local mirror:', e.message);
    }
    // 离线降级：从本地镜像恢复
    try {
      const mirror = readLocalMirror();
      if (mirror) {
        const data = await decryptJSON(mirror.payload, state.masterKey);
        state.accounts = migrateAccounts(data.accounts || []);
        state.snapshots = data.snapshots || [];
        state.groupOrder = data.groupOrder && data.groupOrder.length ? data.groupOrder : [...DEFAULT_GROUP_ORDER];
        state.targetAllocation = data.targetAllocation || {};
        if (data.apiToken) state.apiToken = data.apiToken;
        await enterApp();
        return;
      }
    } catch (e) {
      state.masterKey = null;
      localStorage.removeItem(LOCAL_KEY_STORAGE);
      console.error('Auto-unlock failed (network + mirror):', e);
    }
  }

  // 无缓存 → 显示锁屏
  let meta;
  try {
    meta = await dbGet('meta');
  } catch (e) {
    console.warn('Network unavailable, trying local mirror:', e.message);
    const mirror = readLocalMirror();
    if (mirror && mirror.meta) {
      meta = { id: 'main', salt: mirror.meta.salt, verifier: mirror.meta.verifier, ...(mirror.meta._extra || {}) };
    }
  }
  const errEl = document.getElementById('lock-error');
  errEl.textContent = '';
  document.getElementById('lock-screen').classList.add('active');

  if (!meta) {
    setLockUI('password', true, false);
    document.getElementById('lock-password').focus();
  } else {
    const hasPasskey = !!meta.passkeyCredId;
    const mode = hasPasskey ? 'passkey' : 'password';
    setLockUI(mode, false, hasPasskey);
    if (mode === 'password') document.getElementById('lock-password').focus();
  }
}

// 模式切换（首次设置时）
document.querySelectorAll('#lock-mode-tabs button').forEach(b => {
  b.addEventListener('click', async () => {
    document.getElementById('lock-error').textContent = '';
    const meta = await dbGet('meta');
    setLockUI(b.dataset.mode, !meta, !!(meta && meta.passkeyCredId));
  });
});

function setLockLoading(loading) {
  const spinner = document.getElementById('lock-spinner');
  const submitBtn = document.getElementById('lock-submit');
  const passkeyBtn = document.getElementById('passkey-action');
  const errEl = document.getElementById('lock-error');
  if (loading) {
    errEl.textContent = '';
    spinner.style.display = 'flex';
    submitBtn.disabled = true;
    passkeyBtn.disabled = true;
    submitBtn.style.opacity = '0.5';
    passkeyBtn.style.opacity = '0.5';
  } else {
    spinner.style.display = 'none';
    submitBtn.disabled = false;
    passkeyBtn.disabled = false;
    submitBtn.style.opacity = '';
    passkeyBtn.style.opacity = '';
  }
}

async function handleLockSubmit() {
  setLockLoading(true);
  const errEl = document.getElementById('lock-error');
  errEl.textContent = '';
  try {
  let meta;
  try {
    meta = await dbGet('meta');
  } catch (netErr) {
    console.warn('Network unavailable for meta fetch, trying local mirror:', netErr.message);
    const mirror = readLocalMirror();
    if (mirror && mirror.meta) {
      meta = { id: 'main', salt: mirror.meta.salt, verifier: mirror.meta.verifier, ...(mirror.meta._extra || {}) };
    }
  }

  if (!meta) {
    // 关键保护：本地有镜像就先恢复，绝不让用户创建新账本覆盖
    const localMirror = readLocalMirror();
    if (localMirror) {
      errEl.innerHTML = '检测到云端数据为空，但本地有备份。<br>请<a href="#" id="restore-from-mirror2" style="color:var(--accent);text-decoration:underline">点此从本地恢复</a>，或导入加密备份文件。';
      setLockLoading(false);
      const link = document.getElementById('restore-from-mirror2');
      if (link) link.addEventListener('click', (e) => {
        e.preventDefault();
        offerLocalRestore(localMirror);
      });
      return;
    }

    // 真正的首次设置（密码模式）
    const pwd = document.getElementById('lock-password').value;
    const confirm = document.getElementById('lock-password-confirm').value;
    if (!pwd) { setLockLoading(false); errEl.textContent = '请输入密码'; return; }
    if (pwd.length < 6) { setLockLoading(false); errEl.textContent = '密码至少 6 位字符'; return; }
    if (pwd !== confirm) { setLockLoading(false); errEl.textContent = '两次输入的密码不一致'; return; }

    if (!window.confirm('这将创建一个全新的账本。\n\n如果你之前用过这个应用、有已存在的数据，请取消并先导入加密备份。\n\n确认是首次使用？')) {
      setLockLoading(false);
      return;
    }

    // 1. 生成主密钥
    const masterKey = await crypto.subtle.generateKey(
      { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
    );
    // 2. 用密码派生 wrappingKey 包装主密钥
    const salt = randomBytes(CRYPTO_CONFIG.saltLen);
    const wrappingKey = await deriveKeyFromPassword(pwd, salt);
    const wrappedKeyByPassword = await wrapMasterKey(masterKey, wrappingKey);
    // 3. 用主密钥写一个 verifier 用于以后校验
    const verifier = await encryptJSON({ check: 'asset-ledger-ok' }, masterKey);

    await dbPut('meta', {
      id: 'main',
      salt: bufToB64(salt),
      verifier,
      kdf: 'pbkdf2',
      wrappedKeyByPassword,
    });

    state.masterKey = masterKey;
    const def = buildDefaultData();
    state.accounts = def.accounts;
    state.snapshots = def.snapshots;
    state.groupOrder = def.groupOrder;
    await persistVault();
    await enterApp();
    showToast('已用密码完成初始化');
  } else {
    // 已有：用密码解锁
    const pwd = document.getElementById('lock-password').value;
    if (!pwd) { setLockLoading(false); errEl.textContent = '请输入密码'; return; }
    if (!meta.wrappedKeyByPassword) { setLockLoading(false); errEl.textContent = '此账本未配置密码，请使用 Passkey'; return; }
    try {
      const salt = b64ToBuf(meta.salt);
      const wrappingKey = await deriveKeyFromPassword(pwd, salt);
      const masterKey = await unwrapMasterKey(meta.wrappedKeyByPassword, wrappingKey);
      // 校验
      const checkObj = await decryptJSON(meta.verifier, masterKey);
      if (checkObj.check !== 'asset-ledger-ok') throw new Error();
      state.masterKey = masterKey;
      await loadVaultIntoState();
      await enterApp();
    } catch {
      errEl.textContent = '密码错误';
      setLockLoading(false);
      document.getElementById('lock-password').value = '';
      document.getElementById('lock-password').focus();
    }
  }
  } catch (e) {
    setLockLoading(false);
    errEl.textContent = '解锁失败：' + (e.message || '未知错误');
    console.error('handleLockSubmit error:', e);
  }
}

async function handlePasskeyAction() {
  setLockLoading(true);
  const errEl = document.getElementById('lock-error');
  errEl.textContent = '';
  try {
  let meta;
  try {
    meta = await dbGet('meta');
  } catch (netErr) {
    console.warn('Network unavailable for meta fetch (passkey), trying local mirror:', netErr.message);
    const mirror = readLocalMirror();
    if (mirror && mirror.meta) {
      meta = { id: 'main', salt: mirror.meta.salt, verifier: mirror.meta.verifier, ...(mirror.meta._extra || {}) };
    }
  }

  if (!isPRFSupported()) {
    setLockLoading(false);
    errEl.textContent = '此浏览器不支持 Passkey PRF';
    return;
  }

  if (!meta) {
    // ============================================================
    // 关键保护：D1 没数据时，先检查本地是否有镜像
    // 如果本地有镜像，说明用户之前用过这个应用，可能是 D1 被错误清空
    // 此时绝不让用户继续创建新的 Passkey 覆盖（重复历史的覆盖事故）
    // ============================================================
    const localMirror = readLocalMirror();
    if (localMirror) {
      errEl.innerHTML = '检测到云端数据为空，但本地有备份。<br>请<a href="#" id="restore-from-mirror" style="color:var(--accent);text-decoration:underline">点此从本地恢复</a>，或导入加密备份文件。';
      setLockLoading(false);
      document.getElementById('restore-from-mirror').addEventListener('click', (e) => {
        e.preventDefault();
        offerLocalRestore(localMirror);
      });
      return;
    }

    // 真正的首次设置 Passkey —— 二次确认
    if (!confirm('这将创建一个全新的账本。\n\n如果你确认这是你第一次使用此应用、且没有任何已有数据，请点击"确定"。\n\n如果你之前用过这个应用（即使在另一个域名/设备上），请点击"取消"，然后导入加密备份文件。')) {
      setLockLoading(false);
      return;
    }
    try {
      const { credentialId, prfOutput } = await registerPasskey();
      const wrappingKey = await deriveKeyFromPRF(prfOutput);

      const masterKey = await crypto.subtle.generateKey(
        { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']
      );
      const wrappedKeyByPasskey = await wrapMasterKey(masterKey, wrappingKey);
      const verifier = await encryptJSON({ check: 'asset-ledger-ok' }, masterKey);

      await dbPut('meta', {
        id: 'main',
        salt: bufToB64(randomBytes(CRYPTO_CONFIG.saltLen)),  // 占位
        verifier,
        kdf: 'passkey',
        passkeyCredId: credentialId,
        wrappedKeyByPasskey,
      });
      state.masterKey = masterKey;
      const def = buildDefaultData();
      state.accounts = def.accounts;
      state.snapshots = def.snapshots;
      state.groupOrder = def.groupOrder;
      await persistVault();
      await enterApp();
      showToast('Passkey 注册成功');
    } catch (err) {
      setLockLoading(false);
      errEl.textContent = 'Passkey 注册失败：' + (err.message || '未知错误');
    }
  } else if (meta.passkeyCredId && meta.wrappedKeyByPasskey) {
    // 用 Passkey 解锁
    try {
      const credId = b64ToBuf(meta.passkeyCredId);
      const prfOutput = await getPasskeyPRF(credId);
      const wrappingKey = await deriveKeyFromPRF(prfOutput);
      const masterKey = await unwrapMasterKey(meta.wrappedKeyByPasskey, wrappingKey);
      // 校验
      const checkObj = await decryptJSON(meta.verifier, masterKey);
      if (checkObj.check !== 'asset-ledger-ok') throw new Error('校验失败');
      state.masterKey = masterKey;
      await loadVaultIntoState();
      await enterApp();
    } catch (err) {
      setLockLoading(false);
      errEl.textContent = 'Passkey 解锁失败：' + (err.message || '请重试');
    }
  }
  } catch (e) {
    setLockLoading(false);
    errEl.textContent = '解锁失败：' + (e.message || '未知错误');
    console.error('handlePasskeyAction error:', e);
  }
}

async function loadVaultIntoState() {
  let vault;
  try {
    vault = await dbGet('vault');
  } catch (netErr) {
    console.warn('Network unavailable for vault fetch, trying local mirror:', netErr.message);
    const mirror = readLocalMirror();
    if (mirror && mirror.payload) {
      vault = { payload: mirror.payload };
    }
  }
  if (vault) {
    const data = await decryptJSON(vault.payload, state.masterKey);
    state.accounts = migrateAccounts(data.accounts || []);
    state.snapshots = data.snapshots || [];
    state.groupOrder = data.groupOrder && data.groupOrder.length ? data.groupOrder : [...DEFAULT_GROUP_ORDER];
    state.targetAllocation = data.targetAllocation || {};
    if (data.apiToken) state.apiToken = data.apiToken;

    // 自动修复历史月份格式不规范的快照（如 '2026-4' → '2026-04'）
    let needRepersist = false;
    const seenMonths = new Set();
    const fixedSnapshots = [];
    for (const s of state.snapshots) {
      const fixed = normalizeMonth(s.month);
      if (fixed !== s.month) {
        s.month = fixed;
        needRepersist = true;
      }
      // 去重：同一规范化月份只保留最新的（按 updatedAt）
      if (seenMonths.has(fixed)) {
        const existingIdx = fixedSnapshots.findIndex(x => x.month === fixed);
        if (existingIdx >= 0) {
          if ((s.updatedAt || 0) > (fixedSnapshots[existingIdx].updatedAt || 0)) {
            fixedSnapshots[existingIdx] = s;
          }
          needRepersist = true;
          continue;
        }
      }
      seenMonths.add(fixed);
      fixedSnapshots.push(s);
    }
    if (needRepersist) {
      state.snapshots = fixedSnapshots;
      await persistVault();
      console.log('已自动修复月份格式');
    }

    // 解密成功 → 写本地镜像（保留密文 + 解锁所需 meta，不存明文）
    try {
      const meta = await dbGet('meta');
      if (meta) { state.cachedMeta = meta; writeLocalMirror(meta, vault.payload); }
    } catch (e) { /* 静默 */ }
  } else {
    const def = buildDefaultData();
    state.accounts = def.accounts;
    state.snapshots = def.snapshots;
    state.groupOrder = def.groupOrder;
    await persistVault();
  }
}

async function enterApp() {
  state.unlocked = true;
  if (state.masterKey) await cacheMasterKeyLocally(state.masterKey);
  document.getElementById('lock-screen').classList.remove('active');
  document.getElementById('lock-password').value = '';
  document.getElementById('lock-password-confirm').value = '';
  document.getElementById('lock-error').textContent = '';
  try {
    navTo('dashboard');
  } catch (e) {
    console.error('renderDashboard failed:', e);
    // 渲染错误不影响解锁状态，锁屏已关闭
  }
}

function lockNow() {
  localStorage.removeItem(LOCAL_KEY_STORAGE);
  state.unlocked = false;
  state.masterKey = null;
  state.cachedMeta = null;
  state.accounts = [];
  state.snapshots = [];
  state.groupOrder = [];
  state.editingDraft = null;
  state.editingMonth = null;
  state.entryDirty = false;
  destroyCharts();
  unlockOrInit();
}

document.getElementById('lock-submit').addEventListener('click', handleLockSubmit);
document.getElementById('passkey-action').addEventListener('click', handlePasskeyAction);
document.getElementById('lock-password').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') {
    if (document.getElementById('lock-confirm-group').style.display !== 'none') {
      document.getElementById('lock-password-confirm').focus();
    } else handleLockSubmit();
  }
});
document.getElementById('lock-password-confirm').addEventListener('keydown', (e) => {
  if (e.key === 'Enter') handleLockSubmit();
});
document.getElementById('lock-now-btn').addEventListener('click', lockNow);

// ============================================================
// 工具
// ============================================================
const fmt = (n) => {
  if (n === null || n === undefined || isNaN(n)) return '—';
  const sign = n < 0 ? '-' : '';
  const abs = Math.abs(n);
  return sign + '¥' + abs.toLocaleString('zh-CN', { maximumFractionDigits: 0 });
};
const fmtSign = (n) => {
  if (n === null || n === undefined || isNaN(n)) return '—';
  const sign = n > 0 ? '+' : (n < 0 ? '-' : '');
  return sign + '¥' + Math.abs(n).toLocaleString('zh-CN', { maximumFractionDigits: 0 });
};

// 微型趋势线 SVG · 苹果风格
// 数字弹入动画 · transitions.dev number pop-in
function setDigits(container, str) {
  container.classList.remove('is-animating');
  container.replaceChildren();
  const chars = str.split('');
  chars.forEach((ch, i) => {
    const span = document.createElement('span');
    span.className = 't-digit';
    span.textContent = ch;
    if (i === chars.length - 2) span.dataset.stagger = '1';
    else if (i === chars.length - 1) span.dataset.stagger = '2';
    container.appendChild(span);
  });
  void container.offsetHeight;
  container.classList.add('is-animating');
}
// 文本交换动画 · transitions.dev text swap
function swapText(el, next) {
  const dur = parseFloat(
    getComputedStyle(document.documentElement).getPropertyValue('--text-swap-dur')
  ) || 200;
  el.classList.add('is-exit');
  setTimeout(() => {
    el.textContent = next;
    el.classList.remove('is-exit');
    el.classList.add('is-enter-start');
    void el.offsetHeight;
    el.classList.remove('is-enter-start');
  }, dur);
}
// Hero 总资产：拆 ¥ + 整数 + .小数（弱化货币符号）
function renderHeroValue(n) {
  const el = document.getElementById('kpi-total');
  if (n === null || n === undefined || isNaN(n)) {
    el.innerHTML = '<span class="hero-currency">¥</span>—';
    document.getElementById('waterline-render-target').innerHTML = '';
    return;
  }
  const abs = Math.abs(n);
  const intPart = Math.floor(abs);
  const intStr = intPart.toLocaleString('zh-CN');
  const decimal = (abs - intPart).toFixed(2).slice(1);
  const showDecimal = decimal !== '.00';
  const sign = n < 0 ? '-' : '';
  el.innerHTML = '<span class="hero-currency">' + sign + '¥</span>' +
    '<span class="t-digit-group is-animating" id="kpi-total-int"></span>' +
    (showDecimal ? '<span class="hero-decimal t-digit-group is-animating" id="kpi-total-dec"></span>' : '');
  setDigits(document.getElementById('kpi-total-int'), intStr);
  if (showDecimal) setDigits(document.getElementById('kpi-total-dec'), decimal);

  // 资产水位线
  const latest = state.snapshots.length > 0 ? state.snapshots[state.snapshots.length - 1] : null;
  if (latest) {
    let liqCash = 0, liqInvest = 0, liqLong = 0, totalDebt = 0;
    const activeIds = getActiveAccountIds();
    state.accounts.forEach(acc => {
      if (!activeIds.has(acc.id)) return;
      const bal = Number(latest.entries[acc.id]?.balance || 0);
      if (acc.type === 'liability') {
        if (bal > 0) totalDebt += bal;
      } else if (bal > 0) {
        if (acc.tag === 'cash') liqCash += bal;
        else if (acc.tag === 'investment' || acc.tag === 'credit') liqInvest += bal;
        else liqLong += bal;
      }
    });
    const totalAssets = liqCash + liqInvest + liqLong;
    const safeTotal = totalAssets > 0 ? totalAssets : 1;
    const pCash = (liqCash / safeTotal * 100).toFixed(1);
    const pInvest = (liqInvest / safeTotal * 100).toFixed(1);
    const pLong = (liqLong / safeTotal * 100).toFixed(1);
    const ltv = totalAssets > 0 ? (totalDebt / totalAssets * 100).toFixed(1) : 0;
    document.getElementById('waterline-render-target').innerHTML =
      '<div class="waterline-container">' +
        '<div class="waterline-segment" style="width:' + pCash + '%;background:var(--accent)" title="流动 ' + pCash + '%"></div>' +
        '<div class="waterline-segment" style="width:' + pInvest + '%;background:var(--accent-purple)" title="投资 ' + pInvest + '%"></div>' +
        '<div class="waterline-segment" style="width:' + pLong + '%;background:var(--ink-3)" title="长期 ' + pLong + '%"></div>' +
      '</div>' +
      '<div class="waterline-legend">' +
        '<div class="legend-item"><div class="legend-dot" style="background:var(--accent)"></div>流动 ' + pCash + '%</div>' +
        '<div class="legend-item"><div class="legend-dot" style="background:var(--accent-purple)"></div>投资 ' + pInvest + '%</div>' +
        '<div class="legend-item"><div class="legend-dot" style="background:var(--ink-3)"></div>长期 ' + pLong + '%</div>' +
        '<div class="legend-item" title="资产负债率"><div class="legend-dot" style="background:var(--red)"></div>负债率 <span style="color:' + (ltv > 50 ? 'var(--red)' : 'inherit') + '">' + ltv + '%</span></div>' +
      '</div>';
  }
}


// Hero 内嵌统计值渲染
function renderHeroStatValue(elId, n, withSign) {
  const el = document.getElementById(elId);
  if (!el) return;
  if (n === null || n === undefined || isNaN(n)) {
    el.textContent = '—';
    return;
  }
  const abs = Math.abs(n);
  let symbol = '¥';
  if (withSign) {
    if (n > 0) symbol = '+¥';
    else if (n < 0) symbol = '−¥';
  }
  el.innerHTML = '<span class="hsym">' + symbol + '</span><span class="t-digit-group is-animating" id="hs-' + elId + '-digits"></span>';
  setDigits(document.getElementById('hs-' + elId + '-digits'), abs.toLocaleString('zh-CN', { maximumFractionDigits: 0 }));
}
const ymNow = () => {
  const d = new Date();
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
};
const ymPrev = (ym) => {
  const [y, m] = ym.split('-').map(Number);
  const d = new Date(y, m - 2, 1);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
};
const ymNext = (ym) => {
  const [y, m] = ym.split('-').map(Number);
  const d = new Date(y, m, 1);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
};
// 规范化月份字符串：'2026-4' -> '2026-04'，'2026-04' -> '2026-04'
const normalizeMonth = (ym) => {
  if (!ym || typeof ym !== 'string') return ym;
  const m = ym.match(/^(\d{4})-(\d{1,2})$/);
  if (!m) return ym;
  return m[1] + '-' + m[2].padStart(2, '0');
};
function getAllGroups() {
  const fromAccs = [...new Set(state.accounts.map(a => a.group))];
  const ordered = [...state.groupOrder];
  for (const g of fromAccs) if (!ordered.includes(g)) ordered.push(g);
  return ordered;
}
function groupAccounts() {
  const groups = {};
  for (const g of getAllGroups()) groups[g] = [];
  for (const a of state.accounts) {
    if (!groups[a.group]) groups[a.group] = [];
    groups[a.group].push(a);
  }
  return groups;
}
function showToast(msg, type = 'success') {
  const t = document.getElementById('toast');
  t.classList.remove('show', 'error', 'success');
  const icon = type === 'error' ? '⚠️' : '✓';
  t.innerHTML = '<span class="toast-icon">' + icon + '</span>' + escapeHtml(msg) + '<span class="toast-bar" style="transform:scaleX(1)"></span>';
  if (type === 'error') t.classList.add('error');
  else t.classList.add('success');
  // 触发重排使进度条动画生效
  void t.offsetWidth;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2400);
}
function escapeHtml(s) {
  return String(s).replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
  }[c]));
}
function evalFormula(str) {
  if (!str || str[0] !== '=') return null;
  const expr = str.slice(1).trim();
  if (!expr || !/^[\d+\-*/().%\s]+$/.test(expr)) return null;
  try {
    const result = Function('"use strict"; return (' + expr + ')')();
    if (typeof result !== 'number' || !isFinite(result)) return null;
    return Number(result.toFixed(10));
  } catch { return null; }
}
function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

// ============================================================
// 计算（依赖 state 的部分；纯函数核心见 js/finance.js）
// ============================================================
function getSortedSnapshots() {
  return [...state.snapshots].sort((a, b) => a.month.localeCompare(b.month));
}

function getActiveAccountIds() {
  return new Set(state.accounts.filter(a => {
    if (a.archived) return false;
    if (state.viewMode === 'investment') return (a.tag === 'investment' || a.tag === 'long-term') && a.group !== '其他资产';
    return true;
  }).map(a => a.id));
}

function filterSnapshotEntries(snap, idSet) {
  if (!snap) return null;
  const entries = {};
  for (const [id, v] of Object.entries(snap.entries)) {
    if (idSet.has(id)) entries[id] = v;
  }
  return { ...snap, entries };
}

// ============================================================
// 导航
// ============================================================
function updateBackupBadge() {
  const wrap = document.getElementById('export-data-wrap');
  if (!wrap) return;
  const existing = wrap.querySelector('.backup-badge');
  const lastBackup = parseInt(localStorage.getItem('asset-ledger-last-backup') || '0');
  const sevenDays = 7 * 24 * 3600 * 1000;
  if (lastBackup && (Date.now() - lastBackup > sevenDays)) {
    if (!existing) {
      const badge = document.createElement('span');
      badge.className = 'backup-badge';
      badge.textContent = '该备份了';
      wrap.appendChild(badge);
    }
  } else if (existing) {
    existing.remove();
  }
}

function navTo(page) {
  // 离开旧页面前清理图表实例，防止内存泄漏
  const prev = state.current;
  if (prev === 'dashboard') destroyCharts();
  if (prev === 'history' && returnChart) { returnChart.destroy(); returnChart = null; }
  state.current = page;
  document.querySelectorAll('nav.nav button').forEach(b => b.classList.toggle('active', b.dataset.page === page));
  document.querySelectorAll('.page').forEach(p => p.classList.toggle('active', p.id === 'page-' + page));
  if (page === 'dashboard') { renderDashboard(); updateBackupBadge(); }
  if (page === 'entry') renderEntry();
  if (page === 'history') {
    // 同步历史页视图切换按钮的 active 状态
    document.querySelectorAll('#history-view-toggle button').forEach(b => b.classList.toggle('active', b.dataset.hview === state.historyView));
    renderHistory();
  }
  // 切换页面时关闭抽屉（清理趋势图）
  const drawer = document.getElementById('drawer');
  if (drawer && drawer.classList.contains('open')) closeDrawer();
  requestAnimationFrame(() => { requestAnimationFrame(initScrollReveal); });
  if (page === 'dashboard') {
  }
}
document.querySelectorAll('nav.nav button').forEach(b => {
  b.addEventListener('click', () => navTo(b.dataset.page));
});
document.getElementById('brand-home').addEventListener('click', () => navTo('dashboard'));

// 投资视图切换
document.querySelectorAll('#view-toggle button').forEach(b => {
  b.addEventListener('click', () => {
    state.viewMode = b.dataset.view;
    document.querySelectorAll('#view-toggle button').forEach(x => x.classList.toggle('active', x === b));
    renderDashboard();
  });
});

// 收益率模块 · 期间切换
document.querySelectorAll('#returns-period-tabs button').forEach(b => {
  b.addEventListener('click', () => {
    const period = b.dataset.period;
    if (period === 'custom') {
      // 显示自定义日期范围输入
      const rangeEl = document.getElementById('returns-custom-range');
      if (rangeEl) {
        const isVisible = rangeEl.style.display !== 'none';
        rangeEl.style.display = isVisible ? 'none' : 'flex';
        if (!isVisible) {
          // 默认填入最近 3 个月
          const sorted = getSortedSnapshots();
          if (sorted.length >= 2) {
            document.getElementById('returns-custom-start').value = sorted[Math.max(0, sorted.length - 4)].month;
            document.getElementById('returns-custom-end').value = sorted[sorted.length - 1].month;
          }
        }
      }
      return;
    }
    state.returnPeriod = period;
    // 隐藏自定义范围输入
    const rangeEl = document.getElementById('returns-custom-range');
    if (rangeEl) rangeEl.style.display = 'none';
    renderDashboard();
  });
});

// 自定义日期范围 · 应用
const customApplyBtn = document.getElementById('returns-custom-apply');
if (customApplyBtn) {
  customApplyBtn.addEventListener('click', () => {
    const start = document.getElementById('returns-custom-start').value;
    const end = document.getElementById('returns-custom-end').value;
    if (!start || !end) { showToast('请选择起止月份'); return; }
    if (start > end) { showToast('起始月份不能晚于结束月份'); return; }
    state.returnPeriod = 'custom';
    state.returnCustomStart = start;
    state.returnCustomEnd = end;
    document.getElementById('returns-custom-range').style.display = 'none';
    renderDashboard();
  });
}

// 自定义日期范围 · 取消
const customClearBtn = document.getElementById('returns-custom-clear');
if (customClearBtn) {
  customClearBtn.addEventListener('click', () => {
    document.getElementById('returns-custom-range').style.display = 'none';
    state.returnPeriod = 'ytd';
    renderDashboard();
  });
}

// 收益率模块 · 指标切换
document.querySelectorAll('#returns-indicator-pick button').forEach(b => {
  b.addEventListener('click', () => {
    state.returnIndicator = b.dataset.indicator;
    renderDashboard();
  });
});

// ============================================================
// 抽屉 · drill-down 明细
// ============================================================
const drawerState = {
  type: null,          // 'pnl' | 'flow' | 'ytd'
  month: null,         // 当前展示的月份（YYYY-MM），ytd 类型用作年份
  mode: 'grouped',     // 'brief' | 'full' | 'grouped'，仅 pnl 类型用，默认按分组
};

function openDrawer(type, month) {
  drawerState.type = type;
  drawerState.month = month;
  drawerState.mode = 'grouped';
  renderDrawer();
  const drawer = document.getElementById('drawer');
  drawer.classList.remove('is-closing');
  drawer.classList.add('open');
  document.getElementById('drawer-backdrop').classList.add('open');
  document.body.style.overflow = 'hidden';
}
function closeDrawer() {
  if (trendChartTimer) { clearTimeout(trendChartTimer); trendChartTimer = null; }
  const drawer = document.getElementById('drawer');
  drawer.classList.remove('open');
  drawer.classList.add('is-closing');
  document.getElementById('drawer-backdrop').classList.remove('open');
  document.body.style.overflow = '';
  setTimeout(() => drawer.classList.remove('is-closing'), 150);
  if (accountTrendChart) { accountTrendChart.destroy(); accountTrendChart = null; }
}

function openPieDrilldown(group, accounts, total) {
  drawerState.type = 'assets';
  drawerState.month = null;
  drawerState.mode = 'grouped';
  const sorted = getSortedSnapshots();
  const latest = sorted[sorted.length - 1];
  document.getElementById('drawer-eyebrow').textContent = '资产分布';
  document.getElementById('drawer-title').textContent = group;
  document.getElementById('drawer-amount').textContent = fmt(total);
  document.getElementById('drawer-amount').className = 'drawer-amount';
  document.getElementById('drawer-toolbar').style.display = 'none';
  const body = document.getElementById('drawer-body');
  const palette = [
    getCSSVar('--accent') || '#0071e3',
    getCSSVar('--green') || '#34c759',
    getCSSVar('--yellow') || '#ff9500',
    getCSSVar('--red') || '#ff3b30',
    getCSSVar('--accent-purple') || '#5e6ad2',
    '#8b5cf6', '#38bdf8', '#f59e0b'
  ];
  body.innerHTML = '<div class="drawer-section"><div class="drawer-section-title">账户余额</div></div>' +
    accounts.map((a, i) => {
      const pct = total ? (Math.abs(a.balance) / total * 100).toFixed(1) : 0;
      const color = palette[i % palette.length];
      return '<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:0.5px solid var(--sep)">' +
        '<span style="width:10px;height:10px;border-radius:50%;background:' + color + ';flex-shrink:0"></span>' +
        '<span style="flex:1;font-size:14px">' + escapeHtml(a.name) + '</span>' +
        '<span style="font-family:var(--font-mono);font-size:14px;color:' + (a.type === 'liability' ? 'var(--red)' : 'var(--ink)') + '">' + fmt(Math.abs(a.balance)) + '</span>' +
        '<span style="font-size:12px;color:var(--ink-4);min-width:44px;text-align:right">' + pct + '%</span>' +
        '</div>';
    }).join('') +
    '<div style="display:flex;justify-content:space-between;padding:10px 0 0;font-size:14px;font-weight:600"><span>合计</span><span style="font-family:var(--font-mono)">' + fmt(total) + '</span></div>';
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-backdrop').classList.add('open');
  document.body.style.overflow = 'hidden';
}

let accountTrendChart = null;
let trendChartTimer = null;
function openAccountTrend(accId) {
  const acc = state.accounts.find(a => a.id === accId);
  if (!acc) return;
  const sorted = getSortedSnapshots();
  const labels = sorted.map(s => s.month);
  const data = sorted.map(s => {
    const e = s.entries[accId];
    return e ? (Number(e.balance) || 0) : null;
  });
  const latestBal = data[data.length - 1] || 0;
  document.getElementById('drawer-eyebrow').textContent = '账户钻取';
  document.getElementById('drawer-title').textContent = acc.name + (acc.type === 'liability' ? '（负债）' : '');
  document.getElementById('drawer-amount').textContent = fmt(Math.abs(latestBal));
  document.getElementById('drawer-amount').className = 'drawer-amount';
  document.getElementById('drawer-toolbar').style.display = 'none';

  // 计算累计指标
  let cumPnL = 0, cumFlow = 0;
  for (let i = 0; i < sorted.length; i++) {
    const e = sorted[i].entries[accId];
    if (!e) continue;
    const bal = Number(e.balance) || 0;
    const flow = Number(e.flow) || 0;
    cumFlow += flow;
    if (i > 0) {
      const prevE = sorted[i - 1].entries[accId];
      const prevBal = prevE ? (Number(prevE.balance) || 0) : 0;
      cumPnL += (bal - prevBal - flow);
    }
  }
  // 简易 TWR（近似 Dietz）
  let twr = null;
  if (sorted.length >= 2) {
    let accumReturn = Big(1);
    for (let i = 1; i < sorted.length; i++) {
      const e = sorted[i].entries[accId];
      const prevE = sorted[i - 1].entries[accId];
      if (!e || !prevE) continue;
      const startBal = new Big(prevE.balance || '0').abs();
      const endBal = new Big(e.balance || '0').abs();
      const flow = new Big(e.flow || '0');
      const denominator = startBal.plus(flow.div(2));
      if (!denominator.eq(0)) {
        accumReturn = accumReturn.times(endBal.minus(flow.div(2)).div(denominator));
      }
    }
    twr = accumReturn.minus(1).toNumber();
  }

  // XIRR 现金流（过滤零值，防止 Newton 迭代发散）
  const xirrFlows = [];
  const baseMonth = sorted[0]?.month;
  if (sorted.length >= 2 && baseMonth) {
    const firstBal = Number(sorted[0].entries[accId]?.balance || 0);
    if (firstBal !== 0) xirrFlows.push({ amount: -firstBal, days: 0 });
    for (let i = 1; i < sorted.length; i++) {
      const e = sorted[i].entries[accId];
      if (e && e.flow) {
        const f = Number(e.flow);
        if (f !== 0) xirrFlows.push({ amount: -f, days: daysBetween(baseMonth, sorted[i].month) });
      }
    }
    const lastBal = Number(sorted[sorted.length - 1].entries[accId]?.balance || 0);
    if (lastBal !== 0) xirrFlows.push({ amount: lastBal, days: daysBetween(baseMonth, sorted[sorted.length - 1].month) });
  }
  const xirrVal = xirrFlows.length >= 2 ? calculateXIRR(xirrFlows) : null;

  const body = document.getElementById('drawer-body');
  body.innerHTML = '<div style="display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:6px;margin-bottom:16px">' +
    '<div style="background:var(--bg-2);border-radius:10px;padding:10px 4px;text-align:center"><div style="font-size:11px;color:var(--ink-3);margin-bottom:4px">累计盈亏</div><div style="font-family:var(--font-mono);font-size:14px;font-weight:600;color:var(--' + (cumPnL >= 0 ? 'green' : 'red') + ')">' + fmtSign(cumPnL) + '</div></div>' +
    '<div style="background:var(--bg-2);border-radius:10px;padding:10px 4px;text-align:center"><div style="font-size:11px;color:var(--ink-3);margin-bottom:4px">累计入金</div><div style="font-family:var(--font-mono);font-size:14px;font-weight:600">' + fmtSign(cumFlow) + '</div></div>' +
    '<div style="background:var(--bg-2);border-radius:10px;padding:10px 4px;text-align:center" title="时间加权收益率"><div style="font-size:11px;color:var(--ink-3);margin-bottom:4px">TWR</div><div style="font-family:var(--font-mono);font-size:14px;font-weight:600;color:var(--' + (twr !== null && twr >= 0 ? 'green' : 'red') + ')">' + (twr !== null ? (twr >= 0 ? '+' : '') + (twr * 100).toFixed(1) + '%' : '—') + '</div></div>' +
    '<div style="background:var(--bg-2);border-radius:10px;padding:10px 4px;text-align:center" title="内部收益率 (年化)"><div style="font-size:11px;color:var(--ink-3);margin-bottom:4px">XIRR</div><div style="font-family:var(--font-mono);font-size:14px;font-weight:600;color:var(--' + (xirrVal !== null && xirrVal >= 0 ? 'green' : 'red') + ')">' + (xirrVal !== null ? (xirrVal >= 0 ? '+' : '') + (xirrVal * 100).toFixed(1) + '%' : '—') + '</div></div>' +
    '</div>' +
    '<div style="margin-bottom:4px;font-size:13px;font-weight:600;color:var(--ink-3)">各月余额</div>' +
    '<div style="position:relative;height:220px"><canvas id="trend-canvas"></canvas></div>' +
    '<div style="margin-top:12px;display:grid;grid-template-columns:repeat(auto-fill,minmax(100px,1fr));gap:6px">' +
    labels.map((l, i) => {
      const v = data[i];
      if (v === null) return '';
      return '<div style="background:var(--bg-2);border-radius:8px;padding:6px 10px;text-align:center"><div style="font-size:11px;color:var(--ink-3)">' + l + '</div><div style="font-family:var(--font-mono);font-size:13px;font-weight:600;margin-top:2px">' + fmt(Math.abs(v)) + '</div></div>';
    }).join('') + '</div>';
  document.getElementById('drawer').classList.add('open');
  document.getElementById('drawer-backdrop').classList.add('open');
  document.body.style.overflow = 'hidden';

  // 绘制折线图（渲染后绘制，竞态保护）
  if (trendChartTimer) clearTimeout(trendChartTimer);
  trendChartTimer = setTimeout(() => {
    trendChartTimer = null;
    const canvas = document.getElementById('trend-canvas');
    if (!canvas) return;
    const isDark = document.documentElement.getAttribute('data-theme') === 'dark';
    const colorLine = isDark ? 'rgba(255,255,255,0.08)' : 'rgba(0,0,0,0.06)';
    const colorText = isDark ? '#e5e5ea' : '#1c1c1e';
    if (accountTrendChart) { accountTrendChart.destroy(); accountTrendChart = null; }
    const valid = labels.map((l, i) => ({ l, v: data[i] })).filter(d => d.v !== null);
    if (valid.length < 2) {
      canvas.parentNode.innerHTML = '<div style="text-align:center;padding:60px 0;color:var(--ink-3);font-size:14px">数据不足，至少需要 2 个月</div>';
      return;
    }
    accountTrendChart = new Chart(canvas, {
      type: 'line',
      data: {
        labels: valid.map(d => d.l),
        datasets: [{
          data: valid.map(d => d.v),
          borderColor: '#3b82f6',
          backgroundColor: 'rgba(59,130,246,0.08)',
          borderWidth: 2.5,
          fill: true,
          tension: 0.35,
          pointRadius: 4,
          pointBackgroundColor: '#3b82f6',
          pointBorderColor: isDark ? '#1c1c1e' : '#fff',
          pointBorderWidth: 2,
          pointHoverRadius: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        animation: { duration: 600 },
        scales: {
          x: { display: true, grid: { display: false }, ticks: { color: colorText, font: { size: 11 } } },
          y: { display: true, grid: { color: colorLine }, ticks: { color: colorText, font: { size: 11 }, callback: v => fmt(v) } },
        },
        plugins: { legend: { display: false }, tooltip: { backgroundColor: isDark ? '#2c2c2e' : '#fff', borderColor: colorLine, borderWidth: 1, padding: 12, cornerRadius: 10, callbacks: { label: ctx => ' ' + fmt(ctx.parsed.y) } } },
      },
    });
  }, 50);
}

function renderDrawer() {
  const { type, month, mode } = drawerState;
  const sorted = getSortedSnapshots();
  if (sorted.length === 0) return;

  const eyebrow = document.getElementById('drawer-eyebrow');
  const title = document.getElementById('drawer-title');
  const amountEl = document.getElementById('drawer-amount');
  const toolbar = document.getElementById('drawer-toolbar');
  const body = document.getElementById('drawer-body');

  if (type === 'assets') {
    const isInvestmentView = state.viewMode === 'investment';
    const activeIds = getActiveAccountIds();
    const latest = sorted[sorted.length - 1];
    const filteredLatest = isInvestmentView ? filterSnapshotEntries(latest, activeIds) : latest;
    const total = snapshotTotal(filteredLatest);
    const activeAccounts = state.accounts.filter(a => activeIds.has(a.id));
    eyebrow.textContent = isInvestmentView ? '投资资产' : '总资产';
    title.textContent = '资产明细';
    amountEl.textContent = fmt(total);
    amountEl.className = 'drawer-amount';
    toolbar.style.display = 'none';

    // 按分组聚类
    const grouped = {};
    for (const a of activeAccounts) {
      const bal = Number(latest.entries[a.id]?.balance || 0);
      if (!grouped[a.group]) grouped[a.group] = { total: 0, accounts: [] };
      grouped[a.group].total += bal;
      grouped[a.group].accounts.push({ ...a, balance: bal });
    }
    const groups = state.groupOrder.filter(g => grouped[g] && grouped[g].total !== 0);

    let html = '';
    for (const g of groups) {
      const grp = grouped[g];
      html += '<div class="drawer-section"><div class="drawer-section-title">' + escapeHtml(g) + ' · ' + fmt(grp.total) + '</div>';
      for (const a of grp.accounts) {
        const isNeg = a.type === 'liability' || a.balance < 0;
        html += '<div style="display:flex;align-items:center;gap:12px;padding:8px 0;border-bottom:0.5px solid var(--sep)">' +
          '<span style="flex:1;font-size:14px">' + escapeHtml(a.name) + '</span>' +
          '<span style="font-family:var(--font-mono);font-size:14px;color:' + (isNeg ? 'var(--red)' : 'var(--ink)') + '">' + fmt(Math.abs(a.balance)) + '</span>' +
          '</div>';
      }
      html += '</div>';
    }
    body.innerHTML = html || '<div class="drawer-empty">暂无资产数据</div>';
    return;
  }

  if (type === 'pnl') {
    // 找指定月份的快照
    const targetMonth = month || sorted[sorted.length - 1].month;
    const idx = sorted.findIndex(s => s.month === targetMonth);
    const curr = idx >= 0 ? sorted[idx] : null;
    const prev = idx > 0 ? sorted[idx - 1] : null;

    eyebrow.textContent = '本月盈亏';
    title.textContent = targetMonth;
    if (!curr) {
      amountEl.textContent = '—';
      body.innerHTML = '<div class="drawer-empty">该月份无数据</div>';
      toolbar.style.display = 'none';
      return;
    }
    const pnl = monthlyPnL(curr, prev);
    const isBaseMonth = !prev;
    amountEl.textContent = isBaseMonth ? '基准月' : fmtSign(pnl);
    amountEl.className = 'drawer-amount' + (isBaseMonth ? '' : pnl > 0 ? ' pos' : pnl < 0 ? ' neg' : '');

    toolbar.style.display = isBaseMonth ? 'none' : '';
    if (isBaseMonth) {
      body.innerHTML = '<div class="drawer-empty">基准月 · 无前期数据可对比</div>';
      return;
    }

    // 模式按钮状态
    document.querySelectorAll('[data-drawer-mode]').forEach(b => {
      b.classList.toggle('active', b.dataset.drawerMode === mode);
    });

    // 计算每个账户的明细
    const rows = computePnLRows(curr, prev);

    if (rows.length === 0) {
      body.innerHTML = '<div class="drawer-empty">无账户数据</div>';
      return;
    }

    if (mode === 'brief') {
      body.innerHTML = renderBriefView(rows);
    } else if (mode === 'grouped') {
      body.innerHTML = renderPnLByGroup(rows);
    } else {
      body.innerHTML = renderFullView(rows);
    }
  } else if (type === 'flow') {
    const targetMonth = month || sorted[sorted.length - 1].month;
    const curr = sorted.find(s => s.month === targetMonth);

    eyebrow.textContent = '本月净流';
    title.textContent = targetMonth;
    toolbar.style.display = 'none';

    if (!curr) {
      amountEl.textContent = '—';
      body.innerHTML = '<div class="drawer-empty">该月份无数据</div>';
      return;
    }
    const activeIds = getActiveAccountIds();
    const filteredCurr = filterSnapshotEntries(curr, activeIds);
    const flow = snapshotFlow(filteredCurr);
    amountEl.textContent = fmtSign(flow);
    amountEl.className = 'drawer-amount ' + (flow > 0 ? 'pos' : flow < 0 ? 'neg' : '');

    body.innerHTML = renderFlowView(filteredCurr);
  } else if (type === 'ytd') {
    const year = (month || sorted[sorted.length - 1].month).slice(0, 4);
    const yearSnaps = sorted.filter(s => s.month.startsWith(year));
    const activeIdsYtd = getActiveAccountIds();
    let ytdPnL = 0;
    for (const s of yearSnaps) {
      const p = sorted[sorted.indexOf(s) - 1] || null;
      ytdPnL += monthlyPnL(filterSnapshotEntries(s, activeIdsYtd), filterSnapshotEntries(p, activeIdsYtd));
    }
    eyebrow.textContent = '年内累计盈亏';
    title.textContent = year + ' 年';
    amountEl.textContent = fmtSign(ytdPnL);
    amountEl.className = 'drawer-amount ' + (ytdPnL > 0 ? 'pos' : ytdPnL < 0 ? 'neg' : '');
    toolbar.style.display = 'none';

    body.innerHTML = renderYtdView(year, yearSnaps, sorted);
  } else if (type === 'returns') {
    const latest = sorted[sorted.length - 1];
    eyebrow.textContent = '收益率分析';
    title.textContent = '总资产 ' + fmt(snapshotTotal(latest));
    toolbar.style.display = 'none';

    const metrics = computeReturnMetrics(sorted);
    amountEl.textContent = formatPct(metrics.ytdTWR);
    amountEl.className = 'drawer-amount ' + (metrics.ytdTWR > 0 ? 'pos' : metrics.ytdTWR < 0 ? 'neg' : '');

    body.innerHTML = renderReturnsView(metrics, sorted);
    // 渲染图表（需要在 DOM 插入后执行）
    setTimeout(() => renderReturnChart(metrics), 50);
  }
}

// 计算每个账户对当月盈亏的贡献（只列有变化或入金的账户，遵循当前视图过滤）
function computePnLRows(curr, prev) {
  const activeIds = getActiveAccountIds();
  const rows = [];
  for (const a of state.accounts) {
    if (!activeIds.has(a.id)) continue;
    const currE = curr.entries[a.id];
    const prevE = prev ? prev.entries[a.id] : null;
    if (!currE && !prevE) continue;
    const currBal = currE ? Number(currE.balance) || 0 : 0;
    const prevBal = prevE ? Number(prevE.balance) || 0 : 0;
    const flow = currE ? Number(currE.flow) || 0 : 0;
    const change = currBal - prevBal;
    const pnl = change - flow;
    if (change === 0 && flow === 0) continue;
    rows.push({ account: a, currBal, prevBal, flow, change, pnl });
  }
  // 按盈亏绝对值降序
  rows.sort((x, y) => Math.abs(y.pnl) - Math.abs(x.pnl));
  return rows;
}

function renderBriefView(rows) {
  const maxAbs = Math.max(...rows.map(r => Math.abs(r.pnl)), 1);
  let html = '<div class="drawer-section"><div class="drawer-section-title">账户贡献</div>';
  for (const r of rows) {
    const widthPct = (Math.abs(r.pnl) / maxAbs) * 50; // 各占一半
    const isPos = r.pnl >= 0;
    html += `
      <div class="contrib-row">
        <div class="contrib-row-head">
          <span class="contrib-name">${escapeHtml(r.account.name)}</span>
          <span class="contrib-amount ${isPos ? 'pos' : 'neg'}">${fmtSign(r.pnl)}</span>
        </div>
        <div class="contrib-bar">
          <div class="fill ${isPos ? 'pos' : 'neg'}" style="${isPos ? 'left:50%' : `right:50%`}; width:${widthPct.toFixed(2)}%"></div>
        </div>
      </div>
    `;
  }
  html += '</div>';
  return html;
}

function renderFullView(rows) {
  let html = '<div class="drawer-section"><div class="drawer-section-title">账户明细</div>';
  html += '<table class="contrib-table"><thead><tr><th>账户</th><th>净入金</th><th>变化</th><th>市场盈亏</th></tr></thead><tbody>';
  for (const r of rows) {
    const isPos = r.pnl >= 0;
    html += `<tr>
      <td>${escapeHtml(r.account.name)}</td>
      <td class="num ${r.flow === 0 ? 'muted' : ''}">${fmtSign(r.flow)}</td>
      <td class="num">${fmtSign(r.change)}</td>
      <td class="num pnl-cell ${isPos ? 'pos' : 'neg'}">${fmtSign(r.pnl)}</td>
    </tr>`;
  }
  html += '</tbody></table></div>';
  return html;
}

function renderPnLByGroup(rows) {
  const grouped = {};
  for (const r of rows) {
    if (!grouped[r.account.group]) grouped[r.account.group] = { pnl: 0, flow: 0, count: 0 };
    grouped[r.account.group].pnl += r.pnl;
    grouped[r.account.group].flow += r.flow;
    grouped[r.account.group].count++;
  }
  const entries = Object.entries(grouped).sort((a, b) => Math.abs(b[1].pnl) - Math.abs(a[1].pnl));
  const maxPnL = Math.max(...entries.map(e => Math.abs(e[1].pnl)), 1);
  const totalPnL = entries.reduce((s, e) => s + e[1].pnl, 0);

  let html = '<div class="drawer-section"><div class="drawer-section-title">分组归因</div>';
  // 汇总
  const winGroups = entries.filter(e => e[1].pnl > 0);
  const loseGroups = entries.filter(e => e[1].pnl < 0);
  const winTotal = winGroups.reduce((s, e) => s + e[1].pnl, 0);
  const loseTotal = Math.abs(loseGroups.reduce((s, e) => s + e[1].pnl, 0));
  html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:14px">' +
    '<div style="background:var(--green-soft);border-radius:10px;padding:10px 14px"><div style="font-size:11px;color:var(--green)">盈利分组</div><div style="font-family:var(--font-mono);font-size:18px;font-weight:600;color:var(--green)">' + fmt(winTotal) + '</div><div style="font-size:11px;color:var(--ink-4)">' + winGroups.length + ' 个分组</div></div>' +
    '<div style="background:var(--red-soft);border-radius:10px;padding:10px 14px"><div style="font-size:11px;color:var(--red)">亏损分组</div><div style="font-family:var(--font-mono);font-size:18px;font-weight:600;color:var(--red)">' + fmt(loseTotal) + '</div><div style="font-size:11px;color:var(--ink-4)">' + loseGroups.length + ' 个分组</div></div>' +
    '</div>';

  for (const [group, data] of entries) {
    const barW = (Math.abs(data.pnl) / maxPnL * 100).toFixed(0);
    const isPos = data.pnl >= 0;
    const cls = isPos ? 'pos' : 'neg';
    const barColor = isPos ? 'var(--green)' : 'var(--red)';
    const pct = totalPnL !== 0 ? (data.pnl / totalPnL * 100) : 0;
    html += '<div style="display:flex;align-items:center;gap:10px;padding:7px 0;border-bottom:0.5px solid var(--sep)">' +
      '<span style="flex:0 0 90px;font-size:13px;font-weight:500">' + escapeHtml(group) + '</span>' +
      '<span style="flex:0 0 32px;font-size:10px;color:var(--ink-4)">×' + data.count + '</span>' +
      '<span style="flex:1;height:6px;background:var(--bg-3);border-radius:3px;overflow:hidden"><span style="display:block;width:' + barW + '%;height:100%;background:' + barColor + ';border-radius:3px;transition:width 0.5s ease"></span></span>' +
      '<span style="flex:0 0 80px;font-family:var(--font-mono);font-size:12px;font-weight:600;text-align:right;color:var(--' + (isPos ? 'green' : 'red') + ')">' + fmtSign(data.pnl) + '</span>' +
      '<span style="flex:0 0 46px;font-size:11px;color:var(--ink-4);text-align:right">' + (pct >= 0 ? '+' : '') + pct.toFixed(1) + '%</span>' +
      '</div>';
  }
  html += '</div>';
  return html;
}

function renderFlowView(snap) {
  const activeIds = getActiveAccountIds();
  const inflows = [];
  const outflows = [];
  for (const a of state.accounts) {
    if (!activeIds.has(a.id)) continue;
    const e = snap.entries[a.id];
    if (!e || !e.flow) continue;
    const f = Number(e.flow) || 0;
    if (f > 0) inflows.push({ name: a.name, amount: f });
    else if (f < 0) outflows.push({ name: a.name, amount: f });
  }
  inflows.sort((a, b) => b.amount - a.amount);
  outflows.sort((a, b) => a.amount - b.amount);

  const totalIn = inflows.reduce((s, x) => s + x.amount, 0);
  const totalOut = outflows.reduce((s, x) => s + x.amount, 0);

  let html = '';

  if (inflows.length === 0 && outflows.length === 0) {
    html += '<div class="drawer-empty">本月无资金流动</div>';
    return html;
  }

  if (inflows.length > 0) {
    html += '<div class="drawer-section"><div class="drawer-section-title">资金流入</div>';
    html += '<table class="contrib-table"><tbody>';
    for (const f of inflows) {
      html += `<tr>
        <td>${escapeHtml(f.name)}</td>
        <td class="num pnl-cell pos">${fmtSign(f.amount)}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }

  if (outflows.length > 0) {
    html += '<div class="drawer-section"><div class="drawer-section-title">资金流出</div>';
    html += '<table class="contrib-table"><tbody>';
    for (const f of outflows) {
      html += `<tr>
        <td>${escapeHtml(f.name)}</td>
        <td class="num pnl-cell neg">${fmtSign(f.amount)}</td>
      </tr>`;
    }
    html += '</tbody></table></div>';
  }

  html += `<div class="drawer-section">
    <div class="drawer-section-title">汇总</div>
    <div class="summary-grid">
      <div class="stat"><div class="lbl">流入合计</div><div class="val pos">${fmtSign(totalIn)}</div></div>
      <div class="stat"><div class="lbl">流出合计</div><div class="val neg">${fmtSign(totalOut)}</div></div>
    </div>
  </div>`;

  return html;
}

// ============================================================
// 收益率计算 · 自然年闭区间
// 2026 年 = 2025-12 月末快照 → 2026-12 月末快照（期间净入金扣除）
// 期初取上一年 12 月快照；不存在则退回当年第一份快照（YTD 视角）
// ============================================================
function formatPct(v, digits = 2) {
  if (v === null || v === undefined || isNaN(v) || !isFinite(v)) return '—';
  const sign = v > 0 ? '+' : '';
  return sign + (v * 100).toFixed(digits) + '%';
}

function computeReturnMetrics(allSorted) {
  if (allSorted.length === 0) {
    return { ytdSimple: null, ytdTWR: null, ytdAnn: null, ttmTWR: null, ttmTWRAnn: null,
             ttmMonths: 0, monthsElapsed: 0, ytdPnL: 0, startBalance: 0, series: [], hasYearStart: false };
  }
  const latest = allSorted[allSorted.length - 1];
  const year = latest.month.slice(0, 4);
  const prevYear = String(Number(year) - 1);
  const prevDecMonth = prevYear + '-12';

  const yearSnaps = allSorted.filter(s => s.month.startsWith(year));
  if (yearSnaps.length === 0) {
    return { ytdSimple: null, ytdTWR: null, ytdAnn: null, ttmTWR: null, ttmTWRAnn: null,
             ttmMonths: 0, monthsElapsed: 0, ytdPnL: 0, startBalance: 0, series: [], hasYearStart: false };
  }

  // 期初快照：优先用上一年 12 月
  const yearStartSnap = allSorted.find(s => s.month === prevDecMonth);
  const hasYearStart = !!yearStartSnap;
  const startBalance = yearStartSnap ? snapshotTotal(yearStartSnap) : snapshotTotal(yearSnaps[0]);

  // 计算每段的 prev：
  // - 第一份快照的 prev = yearStartSnap（如果有）
  // - 后续每份 = 前一份
  function prevOf(snap) {
    const idx = allSorted.indexOf(snap);
    return idx > 0 ? allSorted[idx - 1] : null;
  }

  // ========== 年内累计盈亏（市场盈亏，剔除净入金）==========
  let ytdPnL = 0;
  for (const s of yearSnaps) {
    ytdPnL += monthlyPnL(s, prevOf(s));
  }

  // ========== 年内简单收益率 ==========
  const ytdSimple = startBalance > 0 ? Big(ytdPnL).div(Big(startBalance)).toNumber() : null;

  // ========== 年内 TWR ==========
  let twrFactor = Big(1);
  let twrValid = false;
  for (const s of yearSnaps) {
    const p = prevOf(s);
    const periodStart = p ? snapshotTotal(p) : snapshotTotal(s);
    if (periodStart <= 0) continue;
    const r = Big(monthlyPnL(s, p)).div(Big(periodStart));
    twrFactor = twrFactor.times(Big(1).plus(r));
    twrValid = true;
  }
  const ytdTWR = twrValid ? twrFactor.minus(1).toNumber() : null;

  // ========== 年化（基于已记录月数复利推算）==========
  const monthsElapsed = yearSnaps.length;
  const ytdAnn = (ytdTWR !== null && monthsElapsed > 0)
    ? Math.pow(1 + ytdTWR, 12 / monthsElapsed) - 1
    : null;

  // ========== 近 12 个月 TWR + 年化 ==========
  const recent = allSorted.slice(-13);
  let ttmFactor = Big(1);
  let ttmValid = false;
  let ttmMonths = 0;
  for (let i = 1; i < recent.length; i++) {
    const periodStart = snapshotTotal(recent[i - 1]);
    if (periodStart <= 0) continue;
    const r = Big(monthlyPnL(recent[i], recent[i - 1])).div(Big(periodStart));
    ttmFactor = ttmFactor.times(Big(1).plus(r));
    ttmValid = true;
    ttmMonths++;
  }
  const ttmTWR = ttmValid ? ttmFactor.minus(1).toNumber() : null;
  const ttmTWRAnn = (ttmTWR !== null && ttmMonths > 0)
    ? Math.pow(1 + ttmTWR, 12 / ttmMonths) - 1
    : null;

  // ========== 累计曲线（年内每月）==========
  const series = [];
  let cumFactor = Big(1);
  let cumPnL = 0;
  for (const s of yearSnaps) {
    const p = prevOf(s);
    const periodStart = p ? snapshotTotal(p) : snapshotTotal(s);
    const periodPnL = monthlyPnL(s, p);
    if (periodStart > 0) cumFactor = cumFactor.times(Big(1).plus(Big(periodPnL).div(Big(periodStart))));
    cumPnL += periodPnL;
    series.push({
      month: s.month,
      twrCum: cumFactor.minus(1).toNumber(),
      simpleCum: startBalance > 0 ? cumPnL / startBalance : 0,
    });
  }

  return { ytdSimple, ytdTWR, ytdAnn, ttmTWR, ttmTWRAnn, ttmMonths, monthsElapsed,
           ytdPnL, startBalance, series, hasYearStart, year };
}

// ============================================================
// 首页 · 收益率模块（独立 chart-card）
// 数据基于 viewMode 过滤后的快照流，按 returnPeriod 切片
// ============================================================
function valueOfIndicator(p, indicator) {
  if (indicator === 'twr') return p.twrCum;
  if (indicator === 'simple') return p.simpleCum;
  if (indicator === 'xirr') return p.xirrCum;
  return p.pnlCum;
}
function renderReturnsModule(allSorted, onlyActive) {
  if (!allSorted || allSorted.length === 0) return;

  // 补齐图表需要的颜色变量，防止作用域穿透导致的 ReferenceError
  const colorGreen = getCSSVar('--green');
  const colorRed = getCSSVar('--red');
  const colorBg = getCSSVar('--bg-1');
  const colorTooltipBg = getCSSVar('--tooltip-bg');
  const colorLine = getCSSVar('--sep-strong');
  const colorInk = getCSSVar('--ink');
  const colorMute = getCSSVar('--ink-3');
  const colorGrid = getCSSVar('--chart-grid');

  // 1. 切片：按 returnPeriod 取所需 snapshots（含期初）
  const period = state.returnPeriod || 'ytd';
  const indicator = state.returnIndicator || 'twr';
  const filtered = allSorted.map(s => onlyActive(s));
  const periodSnaps = sliceSnapshotsByPeriod(filtered, period);

  // 同步按钮 active 状态（custom 按钮特殊处理）
  document.querySelectorAll('#returns-period-tabs button').forEach(b => {
    if (b.dataset.period === 'custom') {
      b.classList.toggle('active', period === 'custom');
    } else {
      b.classList.toggle('active', b.dataset.period === period);
    }
  });
  document.querySelectorAll('#returns-indicator-pick button').forEach(b => {
    b.classList.toggle('active', b.dataset.indicator === indicator);
  });

  // 2. 没有有效切片时显示空状态
  const emptyEl = document.getElementById('returns-chart-empty');
  const canvas = document.getElementById('returns-chart');
  const primaryEl = document.getElementById('returns-primary-value');
  const primaryLabelEl = document.getElementById('returns-primary-label');
  const secondaryEl = document.getElementById('returns-secondary-value');
  const secondaryLabelEl = document.getElementById('returns-secondary-label');
  const rangeEl = document.getElementById('returns-period-range');
  const formulaEl = document.getElementById('returns-formula-note');

  if (!periodSnaps || periodSnaps.points.length < 2) {
    primaryEl.textContent = '—';
    primaryEl.className = 'returns-summary-value';
    secondaryEl.textContent = '—';
    secondaryEl.className = 'returns-summary-value';
    rangeEl.textContent = '—';
    if (returnsModuleChart) { returnsModuleChart.destroy(); returnsModuleChart = null; }
    emptyEl.style.display = 'flex';
    return;
  }
  emptyEl.style.display = 'none';

  // 3. 计算累计 TWR / 简单 / 盈亏额 序列
  const series = computePeriodSeries(periodSnaps);
  // series.points: [{ month, twrCum, simpleCum, pnlCum }]

  // 4. 主指标和辅助数字
  const last = series.points[series.points.length - 1];
  let primaryValue, primaryLabel, secondaryValue, secondaryLabel;
  if (indicator === 'twr') {
    primaryValue = last.twrCum;
    primaryLabel = '收益率 · TWR';
    secondaryValue = last.pnlCum;
    secondaryLabel = '累计盈亏';
    formulaEl.textContent = 'TWR 累计收益率剔除入金/出金影响';
  } else if (indicator === 'simple') {
    primaryValue = last.simpleCum;
    primaryLabel = '收益率 · 简单加权';
    secondaryValue = last.pnlCum;
    secondaryLabel = '累计盈亏';
    formulaEl.textContent = '简单收益率 = 累计盈亏 / 期初余额';
  } else if (indicator === 'xirr') {
    primaryValue = last.xirrCum;
    primaryLabel = '收益率 · XIRR';
    secondaryValue = last.twrCum;
    secondaryLabel = 'TWR 对比';
    formulaEl.textContent = 'XIRR 内部收益率（年化）—— 考虑每笔现金流的时间价值';
  } else { // amount
    primaryValue = last.pnlCum;
    primaryLabel = '累计盈亏';
    secondaryValue = last.twrCum;
    secondaryLabel = '收益率 · TWR';
    formulaEl.textContent = '累计盈亏额 = 期间所有市场盈亏之和（已剔除净流）';
  }

  // 渲染主指标
  if (indicator === 'amount') {
    primaryEl.textContent = fmtSign(primaryValue);
    primaryEl.className = 'returns-summary-value ' + (primaryValue > 0 ? 'pos' : primaryValue < 0 ? 'neg' : '');
    secondaryEl.textContent = secondaryValue === null ? '—' : (secondaryValue >= 0 ? '+' : '') + (secondaryValue * 100).toFixed(2) + '%';
    secondaryEl.className = 'returns-summary-value ' + (secondaryValue > 0 ? 'pos' : secondaryValue < 0 ? 'neg' : '');
  } else if (indicator === 'xirr') {
    primaryEl.textContent = primaryValue === null ? '—' : (primaryValue >= 0 ? '+' : '') + (primaryValue * 100).toFixed(2) + '%';
    primaryEl.className = 'returns-summary-value' + (primaryValue > 0 ? ' pos' : primaryValue < 0 ? ' neg' : '');
    secondaryEl.textContent = secondaryValue === null ? '—' : (secondaryValue >= 0 ? '+' : '') + (secondaryValue * 100).toFixed(2) + '%';
    secondaryEl.className = 'returns-summary-value' + (secondaryValue > 0 ? ' pos' : secondaryValue < 0 ? ' neg' : '');
  } else {
    primaryEl.textContent = primaryValue === null ? '—' : (primaryValue >= 0 ? '+' : '') + (primaryValue * 100).toFixed(2) + '%';
    primaryEl.className = 'returns-summary-value ' + (primaryValue > 0 ? 'pos' : primaryValue < 0 ? 'neg' : '');
    secondaryEl.textContent = fmtSign(secondaryValue);
    secondaryEl.className = 'returns-summary-value ' + (secondaryValue > 0 ? 'pos' : secondaryValue < 0 ? 'neg' : '');
  }
  primaryLabelEl.textContent = primaryLabel;
  secondaryLabelEl.textContent = secondaryLabel;
  rangeEl.textContent = series.points[0].month + ' → ' + last.month;

  // 5. 绘制走势图（正负双色面积）
  if (returnsModuleChart) { returnsModuleChart.destroy(); returnsModuleChart = null; }
  const dataPoints = series.points;
  const labels = dataPoints.map(p => p.month);
  const isPct = indicator !== 'amount';
  const dataValues = dataPoints.map(p => isPct ? (valueOfIndicator(p, indicator) * 100) : valueOfIndicator(p, indicator));

  const posValues = dataValues.map(v => Math.max(0, v));
  const negValues = dataValues.map(v => Math.min(0, v));

  const greenRgb = hexToRgb(colorGreen);
  const redRgb = hexToRgb(colorRed);

  const retCtx = canvas.getContext('2d');
  const greenGrad = retCtx.createLinearGradient(0, 0, 0, 220);
  greenGrad.addColorStop(0, `rgba(${greenRgb},0.25)`);
  greenGrad.addColorStop(1, `rgba(${greenRgb},0)`);

  const redGrad = retCtx.createLinearGradient(0, 220, 0, 0);
  redGrad.addColorStop(0, `rgba(${redRgb},0.25)`);
  redGrad.addColorStop(1, `rgba(${redRgb},0)`);

  returnsModuleChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          data: posValues,
          borderColor: colorGreen,
          borderWidth: 3,
          fill: true,
          backgroundColor: greenGrad,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 6,
          pointBackgroundColor: colorGreen,
          pointBorderColor: colorBg,
          pointBorderWidth: 2,
          pointHoverBorderWidth: 3,
        },
        {
          data: negValues,
          borderColor: colorRed,
          borderWidth: 3,
          fill: true,
          backgroundColor: redGrad,
          tension: 0.4,
          pointRadius: 0,
          pointHoverRadius: 6,
          pointBackgroundColor: colorRed,
          pointBorderColor: colorBg,
          pointBorderWidth: 2,
          pointHoverBorderWidth: 3,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 800, easing: 'easeOutQuart' },
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(28,28,30,0.85)',
          titleFont: { size: 12, weight: 'normal' },
          bodyFont: { size: 14, weight: 'bold', family: MONO_FONT },
          padding: 10,
          cornerRadius: 8,
          displayColors: false,
          filter: (ctx) => ctx.datasetIndex === 0,
          callbacks: {
            label: (ctx) => {
              const v = dataValues[ctx.dataIndex];
              return isPct
                ? (v >= 0 ? '+' : '') + v.toFixed(2) + '%'
                : fmt(v);
            },
          },
        },
        zeroLine: {
          afterDraw(chart) {
            const yScale = chart.scales.y;
            const zeroY = yScale.getPixelForValue(0);
            if (zeroY <= yScale.top || zeroY >= yScale.bottom) return;
            const ctx = chart.ctx;
            ctx.save();
            ctx.beginPath();
            ctx.moveTo(chart.scales.x.left, zeroY);
            ctx.lineTo(chart.scales.x.right, zeroY);
            ctx.strokeStyle = getCSSVar('--ink-3') || '#8a8f98';
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 5]);
            ctx.stroke();
            ctx.restore();
          },
        },
        crosshair: {
          afterDraw(chart) {
            if (!chart.tooltip || !chart.tooltip._active || !chart.tooltip._active.length) return;
            const ctx = chart.ctx;
            const x = chart.tooltip._active[0].element.x;
            const topY = chart.scales.y.top;
            const bottomY = chart.scales.y.bottom;
            ctx.save();
            ctx.beginPath();
            ctx.moveTo(x, topY);
            ctx.lineTo(x, bottomY);
            ctx.strokeStyle = getCSSVar('--sep-strong') || 'rgba(255,255,255,0.08)';
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.stroke();
            ctx.restore();
          },
        },
      },
      scales: {
        x: {
          display: true,
          grid: { display: false, drawBorder: false },
          ticks: { color: colorMute, font: { size: 11 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 6 },
        },
        y: {
          display: false,
        },
      },
    },
  });
}

// 按 period 切出 snapshots：第一份是"期初"，后面是各个数据点
function sliceSnapshotsByPeriod(allSorted, period) {
  if (allSorted.length === 0) return null;

  if (period === 'custom') {
    const cs = state.returnCustomStart;
    const ce = state.returnCustomEnd;
    if (!cs || !ce) return { points: [] };
    // 找到起始月份的前一个快照作为期初
    const startIdx = allSorted.findIndex(s => s.month === cs);
    if (startIdx < 0) return { points: [] };
    const inception = startIdx > 0 ? allSorted[startIdx - 1] : null;
    const range = allSorted.filter(s => s.month >= cs && s.month <= ce);
    if (range.length === 0) return { points: [] };
    return {
      points: [inception, ...range].filter(Boolean),
      hasInception: !!inception,
    };
  }

  if (period === 'ytd') {
    const latest = allSorted[allSorted.length - 1];
    const year = latest.month.slice(0, 4);
    const prevDec = String(Number(year) - 1) + '-12';
    const yearStartIdx = allSorted.findIndex(s => s.month === prevDec);
    const yearStart = yearStartIdx >= 0 ? allSorted[yearStartIdx] : null;
    const yearSnaps = allSorted.filter(s => s.month.startsWith(year));
    if (yearSnaps.length === 0) return { points: [] };
    return {
      points: [yearStart, ...yearSnaps].filter(Boolean),
      hasInception: !!yearStart, // 是否有真正的期初快照
    };
  }

  // 1m / 3m / 6m: 取最近 N+1 份（N 期间 + 1 期初）
  const months = period === '1m' ? 1 : period === '3m' ? 3 : 6;
  const n = months + 1;
  const slice = allSorted.slice(-n);
  return { points: slice, hasInception: slice.length === n };
}

// 计算每个数据点的累计指标
function computePeriodSeries(periodSnaps) {
  const points = periodSnaps.points;
  if (points.length < 2) return { points: [] };

  const inception = points[0];
  const startBalance = snapshotTotal(inception);
  const inceptionMonth = inception.month;

  let twrFactor = Big(1);
  let pnlCum = 0;
  const out = [];

  for (let i = 1; i < points.length; i++) {
    const curr = points[i];
    const prev = points[i - 1];
    const periodStart = snapshotTotal(prev);
    const periodPnL = monthlyPnL(curr, prev);
    pnlCum += periodPnL;
    if (periodStart > 0) twrFactor = twrFactor.times(Big(1).plus(Big(periodPnL).div(Big(periodStart))));

    // XIRR at this point
    let xirrAtPoint = null;
    if (startBalance > 0) {
      const xf = [{ amount: -startBalance, days: 0 }];
      for (let j = 1; j <= i; j++) {
        const flow = snapshotFlow(points[j]);
        if (flow !== 0) xf.push({ amount: -flow, days: daysBetween(inceptionMonth, points[j].month) });
      }
      const endBal = snapshotTotal(curr);
      if (endBal > 0) {
        xf.push({ amount: endBal, days: daysBetween(inceptionMonth, curr.month) });
        xirrAtPoint = calculateXIRR(xf);
      }
    }

    out.push({
      month: curr.month,
      twrCum: twrFactor.minus(1).toNumber(),
      simpleCum: startBalance > 0 ? pnlCum / startBalance : 0,
      pnlCum: pnlCum,
      xirrCum: xirrAtPoint,
    });
  }

  out.unshift({
    month: inception.month,
    twrCum: 0, simpleCum: 0, pnlCum: 0, xirrCum: null,
  });

  return { points: out };
}

function renderReturnsView(m, sorted) {
  const latestTotal = snapshotTotal(sorted[sorted.length - 1]);
  let html = '';

  // 顶部对比卡：简单 vs TWR
  html += `<div class="drawer-section">
    <div class="drawer-section-title">${m.year} 年内</div>
    <div class="summary-grid">
      <div class="stat">
        <div class="lbl">简单收益率</div>
        <div class="val ${m.ytdSimple > 0 ? 'pos' : m.ytdSimple < 0 ? 'neg' : ''}">${formatPct(m.ytdSimple)}</div>
      </div>
      <div class="stat">
        <div class="lbl">时间加权 TWR</div>
        <div class="val ${m.ytdTWR > 0 ? 'pos' : m.ytdTWR < 0 ? 'neg' : ''}">${formatPct(m.ytdTWR)}</div>
      </div>
    </div>
    <p style="font-size:11px; color: var(--ink-3); margin-top:10px; line-height:1.55;">
      简单收益率 = 累计盈亏 / 期初总资产<br>
      TWR 剔除入金/出金，更接近真实投资回报<br>
      ${m.hasYearStart ? '期初取 ' + (Number(m.year) - 1) + '-12 月末快照' : '⚠️ 无上年 12 月快照，期初用当年首份快照（YTD 视角）'}
    </p>
  </div>`;

  // 趋势图
  html += `<div class="drawer-section">
    <div class="drawer-section-title">收益率走势</div>
    <div style="position: relative; height: 240px;"><canvas id="return-chart"></canvas></div>
  </div>`;

  // 年化
  html += `<div class="drawer-section">
    <div class="drawer-section-title">年化收益率（推算）</div>
    <div class="summary-grid">
      <div class="stat">
        <div class="lbl">年内推算年化</div>
        <div class="val ${m.ytdAnn > 0 ? 'pos' : m.ytdAnn < 0 ? 'neg' : ''}">${formatPct(m.ytdAnn)}</div>
      </div>
      <div class="stat">
        <div class="lbl">近 12 月年化</div>
        <div class="val ${m.ttmTWRAnn > 0 ? 'pos' : m.ttmTWRAnn < 0 ? 'neg' : ''}">${formatPct(m.ttmTWRAnn)}</div>
      </div>
    </div>
    <p style="font-size:11px; color: var(--ink-3); margin-top:10px; line-height:1.55;">
      年化 = (1 + 累计 TWR) ^ (12 / 月数) − 1<br>
      ${m.monthsElapsed < 6 ? '⚠️ 数据不足 6 个月时年化波动较大，仅供参考' : '基于现有数据复利推算'}
    </p>
  </div>`;

  // 关键参数
  html += `<div class="drawer-section">
    <div class="drawer-section-title">参考</div>
    <table class="contrib-table"><tbody>
      <tr><td>期初总资产</td><td class="num">${fmt(m.startBalance)}</td></tr>
      <tr><td>当前总资产</td><td class="num">${fmt(latestTotal)}</td></tr>
      <tr><td>年内累计盈亏</td><td class="num ${m.ytdPnL >= 0 ? 'pos' : 'neg'}">${fmtSign(m.ytdPnL)}</td></tr>
      <tr><td>年内已记录月数</td><td class="num">${m.monthsElapsed}</td></tr>
    </tbody></table>
  </div>`;

  return html;
}

let returnChart = null;
let returnsModuleChart = null;
function renderReturnChart(metrics) {
  if (returnChart) { returnChart.destroy(); returnChart = null; }
  const canvas = document.getElementById('return-chart');
  if (!canvas || !metrics.series || metrics.series.length === 0) return;

  const colorMute = getCSSVar('--ink-3');
  const colorGrid = getCSSVar('--chart-grid');
  const colorAccent = getCSSVar('--accent');
  const colorBg = getCSSVar('--bg-1');
  const colorTooltipBg = getCSSVar('--tooltip-bg');
  const colorLine = getCSSVar('--sep-strong');
  const colorInk = getCSSVar('--ink');

  const labels = metrics.series.map(p => p.month.slice(5) + '月');
  const twrData = metrics.series.map(p => p.twrCum * 100);
  const simpleData = metrics.series.map(p => p.simpleCum * 100);

  returnChart = new Chart(canvas, {
    type: 'line',
    data: {
      labels,
      datasets: [
        {
          label: 'TWR 累计',
          data: twrData,
          borderColor: colorAccent,
          backgroundColor: 'transparent',
          tension: 0.3,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: colorAccent,
          pointBorderColor: colorBg,
          pointBorderWidth: 1.5,
        },
        {
          label: '简单累计',
          data: simpleData,
          borderColor: getCSSVar('--accent-purple') || '#8b5cf6',
          backgroundColor: 'rgba(139,92,246,0.06)',
          tension: 0.3,
          borderWidth: 2,
          borderDash: [],
          pointRadius: 2,
          pointBackgroundColor: '#38bdf8',
          pointBorderColor: colorBg,
          pointBorderWidth: 1.5,
          fill: true,
        },
      ],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: 'top', align: 'end',
          labels: { boxWidth: 16, boxHeight: 4, padding: 16, font: { size: 12, family: UI_FONT }, usePointStyle: true, pointStyle: 'line' },
        },
        tooltip: {
          backgroundColor: colorTooltipBg, borderColor: colorLine, borderWidth: 1,
          titleColor: colorInk, bodyColor: colorInk, padding: 12, cornerRadius: 10,
          callbacks: { label: (ctx) => '  ' + ctx.dataset.label + ': ' + (ctx.parsed.y >= 0 ? '+' : '') + ctx.parsed.y.toFixed(2) + '%' },
        },
      },
      scales: {
        x: { grid: { display: false }, border: { display: false }, ticks: { color: colorMute } },
        y: {
          grid: { color: colorGrid }, border: { display: false },
          ticks: { color: colorMute, callback: (v) => (v >= 0 ? '+' : '') + v.toFixed(1) + '%' },
        },
      },
    },
  });
}

function renderYtdView(year, yearSnaps, allSorted) {
  if (yearSnaps.length === 0) {
    return '<div class="drawer-empty">' + year + ' 年尚无快照</div>';
  }
  const activeIds = getActiveAccountIds();
  // 计算每月数据（过滤视图）
  const monthRows = yearSnaps.map(s => {
    const idx = allSorted.indexOf(s);
    const prev = idx > 0 ? allSorted[idx - 1] : null;
    const filteredS = filterSnapshotEntries(s, activeIds);
    const filteredP = filterSnapshotEntries(prev, activeIds);
    return {
      month: s.month,
      pnl: monthlyPnL(filteredS, filteredP),
      flow: snapshotFlow(filteredS),
    };
  });
  monthRows.sort((a, b) => b.month.localeCompare(a.month)); // 最新在前

  const maxAbs = Math.max(...monthRows.map(r => Math.abs(r.pnl)), 1);

  let html = '<div class="drawer-section"><div class="drawer-section-title">月度盈亏</div>';
  html += '<div class="month-list">';
  for (const r of monthRows) {
    const widthPct = (Math.abs(r.pnl) / maxAbs) * 50;
    const isPos = r.pnl >= 0;
    html += `<div class="month-row" data-month="${r.month}">
      <div class="m-label">${r.month.slice(5)}月</div>
      <div class="m-bar">
        <div class="fill ${isPos ? 'pos' : 'neg'}" style="background:${isPos ? 'var(--green)' : 'var(--red)'}; ${isPos ? 'left:50%' : 'right:50%'}; width:${widthPct.toFixed(2)}%"></div>
      </div>
      <div class="m-amount ${isPos ? 'pos' : 'neg'}">${fmtSign(r.pnl)}</div>
    </div>`;
  }
  html += '</div></div>';

  // 总结
  const totalPnL = monthRows.reduce((s, r) => s + r.pnl, 0);
  const totalFlow = monthRows.reduce((s, r) => s + r.flow, 0);
  html += `<div class="drawer-section">
    <div class="drawer-section-title">${year} 年汇总</div>
    <div class="summary-grid">
      <div class="stat"><div class="lbl">累计盈亏</div><div class="val ${totalPnL >= 0 ? 'pos' : 'neg'}">${fmtSign(totalPnL)}</div></div>
      <div class="stat"><div class="lbl">累计净流</div><div class="val">${fmtSign(totalFlow)}</div></div>
    </div>
  </div>`;

  // 账户级累计盈亏拆解
  // 对年内每个月，对每个账户算出当月市场盈亏（变化 - 入金），然后跨月累加
  const accPnL = {};  // accId -> 累计盈亏
  for (const s of yearSnaps) {
    const idx = allSorted.indexOf(s);
    const prev = idx > 0 ? allSorted[idx - 1] : null;
    for (const a of state.accounts) {
      if (!activeIds.has(a.id)) continue;
      const currE = s.entries[a.id];
      const prevE = prev ? prev.entries[a.id] : null;
      if (!currE && !prevE) continue;
      const currBal = currE ? Number(currE.balance) || 0 : 0;
      const prevBal = prevE ? Number(prevE.balance) || 0 : 0;
      const flow = currE ? Number(currE.flow) || 0 : 0;
      const pnl = (currBal - prevBal) - flow;
      if (pnl === 0) continue;
      accPnL[a.id] = (accPnL[a.id] || 0) + pnl;
    }
  }
  const accRows = Object.entries(accPnL)
    .map(([accId, pnl]) => {
      const acc = state.accounts.find(a => a.id === accId);
      return acc ? { name: acc.name, group: acc.group, pnl } : null;
    })
    .filter(r => r && Math.abs(r.pnl) > 0.5);

  // 按分组聚合 YTD 盈亏（在账户明细之前展示）
  const groupYtdPnL = {};
  for (const r of accRows) {
    groupYtdPnL[r.group] = (groupYtdPnL[r.group] || 0) + r.pnl;
  }
  const groupEntries = Object.entries(groupYtdPnL).sort((a, b) => Math.abs(b[1]) - Math.abs(a[1]));
  if (groupEntries.length > 0) {
    const maxGrp = Math.max(...groupEntries.map(e => Math.abs(e[1])), 1);
    const winGrp = groupEntries.filter(e => e[1] > 0);
    const loseGrp = groupEntries.filter(e => e[1] < 0);
    html += '<div class="drawer-section"><div class="drawer-section-title">分组归因</div>';
    html += '<div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">' +
      '<div style="background:var(--green-soft);border-radius:8px;padding:8px 12px"><div style="font-size:10px;color:var(--green)">盈利分组</div><div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:var(--green)">' + fmt(winGrp.reduce((s, e) => s + e[1], 0)) + '</div></div>' +
      '<div style="background:var(--red-soft);border-radius:8px;padding:8px 12px"><div style="font-size:10px;color:var(--red)">亏损分组</div><div style="font-family:var(--font-mono);font-size:14px;font-weight:700;color:var(--red)">' + fmt(Math.abs(loseGrp.reduce((s, e) => s + e[1], 0))) + '</div></div>' +
      '</div>';
    for (const [group, pnl] of groupEntries) {
      const barW = (Math.abs(pnl) / maxGrp * 100).toFixed(0);
      const isPos = pnl >= 0;
      const barColor = isPos ? 'var(--green)' : 'var(--red)';
      const pct = totalPnL !== 0 ? (pnl / totalPnL * 100) : 0;
      html += '<div style="display:flex;align-items:center;gap:8px;padding:5px 0;border-bottom:0.5px solid var(--sep);font-size:12px">' +
        '<span style="width:80px;font-weight:500">' + escapeHtml(group) + '</span>' +
        '<span style="flex:1;height:5px;background:var(--bg-3);border-radius:3px;overflow:hidden"><span style="display:block;width:' + barW + '%;height:100%;background:' + barColor + ';border-radius:3px"></span></span>' +
        '<span style="font-family:var(--font-mono);font-weight:600;color:' + barColor + ';min-width:60px;text-align:right">' + fmtSign(pnl) + '</span>' +
        '<span style="color:var(--ink-4);min-width:40px;text-align:right;font-size:11px">' + (pct >= 0 ? '+' : '') + pct.toFixed(1) + '%</span>' +
        '</div>';
    }
    html += '</div>';
  }

  if (accRows.length > 0) {
    const winners = accRows.filter(r => r.pnl > 0).sort((a, b) => b.pnl - a.pnl);
    const losers = accRows.filter(r => r.pnl < 0).sort((a, b) => a.pnl - b.pnl);
    const maxAccAbs = Math.max(...accRows.map(r => Math.abs(r.pnl)), 1);

    const renderAccBlock = (rows, isWin) => {
      let h = '';
      for (const r of rows) {
        const widthPct = (Math.abs(r.pnl) / maxAccAbs) * 50;
        h += `<div class="contrib-row">
          <div class="contrib-row-head">
            <span class="contrib-name">${escapeHtml(r.name)}</span>
            <span class="contrib-amount ${isWin ? 'pos' : 'neg'}">${fmtSign(r.pnl)}</span>
          </div>
          <div class="contrib-bar">
            <div class="fill ${isWin ? 'pos' : 'neg'}" style="${isWin ? 'left:50%' : 'right:50%'}; width:${widthPct.toFixed(2)}%"></div>
          </div>
        </div>`;
      }
      return h;
    };

    if (winners.length > 0) {
      html += '<div class="drawer-section">';
      html += '<div class="drawer-section-title">盈利账户</div>';
      html += renderAccBlock(winners, true);
      html += '</div>';
    }
    if (losers.length > 0) {
      html += '<div class="drawer-section">';
      html += '<div class="drawer-section-title">亏损账户</div>';
      html += renderAccBlock(losers, false);
      html += '</div>';
    }
  }

  return html;
}

// 事件绑定
document.getElementById('drawer-close').addEventListener('click', closeDrawer);
document.getElementById('drawer-backdrop').addEventListener('click', closeDrawer);
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && document.getElementById('drawer').classList.contains('open')) {
    closeDrawer();
  }
});
// Hero 卡片点击 → 资产明细抽屉
document.querySelector('.hero-block').addEventListener('click', (e) => {
  if (e.target.closest('[data-drill]') || e.target.closest('#view-toggle')) return;
  if (state.snapshots.length === 0) { showToast('尚无数据'); return; }
  openDrawer('assets');
});

document.querySelectorAll('[data-drill]').forEach(el => {
  el.addEventListener('click', () => {
    if (state.snapshots.length === 0) {
      showToast('尚无数据');
      return;
    }
    const sorted = getSortedSnapshots();
    const latestMonth = sorted[sorted.length - 1].month;
    openDrawer(el.dataset.drill, latestMonth);
  });
});
document.querySelectorAll('[data-drawer-mode]').forEach(b => {
  b.addEventListener('click', () => {
    drawerState.mode = b.dataset.drawerMode;
    renderDrawer();
  });
});
// 月份行点击 → 跳到该月盈亏抽屉
document.getElementById('drawer-body').addEventListener('click', (e) => {
  const row = e.target.closest('[data-month]');
  if (row) {
    openDrawer('pnl', row.dataset.month);
  }
});

// ============================================================
// 概览
// ============================================================
let charts = {};
function destroyCharts() {
  Object.values(charts).forEach(c => c && c.destroy());
  charts = {};
  if (returnsModuleChart) { returnsModuleChart.destroy(); returnsModuleChart = null; }
}
const cssVarCache = {};
function getCSSVar(name) {
  if (!cssVarCache[name]) {
    cssVarCache[name] = getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  }
  return cssVarCache[name];
}
function hexToRgb(hex) {
  hex = hex.replace('#', '');
  if (hex.length === 3) hex = hex.split('').map(c => c + c).join('');
  const n = parseInt(hex, 16);
  return `${(n >> 16) & 255},${(n >> 8) & 255},${n & 255}`;
}

function renderDashboard() {
  destroyCharts();
  const sorted = getSortedSnapshots();

  document.getElementById('page-dashboard').classList.toggle('is-empty', sorted.length === 0);
  if (sorted.length === 0) {
    document.getElementById('kpi-total').innerHTML = '<span class="hero-currency">¥</span>—';
    document.getElementById('kpi-total-sub').textContent = '尚无快照，请先到「录入」页创建第一份记录';
    document.getElementById('kpi-total-pill').classList.remove('show');
    ['pnl', 'flow', 'ytd'].forEach(k => {
      const el = document.getElementById('hero-stat-' + k);
      if (el) el.textContent = '—';
      const trEl = document.getElementById('hero-stat-' + k + '-trend');
      if (trEl) { trEl.textContent = ''; trEl.className = 'hero-stat-trend'; }
      const subEl = document.getElementById('hero-stat-' + k + '-sub');
      if (subEl) subEl.textContent = '';
    });
    // 收益率模块清空
    document.getElementById('returns-primary-value').textContent = '—';
    document.getElementById('returns-primary-value').className = 'returns-summary-value';
    document.getElementById('returns-secondary-value').textContent = '—';
    document.getElementById('returns-secondary-value').className = 'returns-summary-value';
    document.getElementById('returns-period-range').textContent = '—';
    if (returnsModuleChart) { returnsModuleChart.destroy(); returnsModuleChart = null; }
    document.getElementById('returns-chart-empty').style.display = 'flex';
    const chEl = document.getElementById('ch-total');
    if (chEl) chEl.innerHTML = '<span class="ch-currency">¥</span>—';
    return;
  }

  const activeAccIds = getActiveAccountIds();
  const isInvestmentView = state.viewMode === 'investment';
  function onlyActive(snap) { return filterSnapshotEntries(snap, activeAccIds); }

  const latest = sorted[sorted.length - 1];
  const prev = sorted.length >= 2 ? sorted[sorted.length - 2] : null;
  const total = snapshotTotal(onlyActive(latest));
  const prevTotal = prev ? snapshotTotal(onlyActive(prev)) : null;
  const pnl = monthlyPnL(onlyActive(latest), onlyActive(prev));
  const flow = snapshotFlow(onlyActive(latest));

  const yearOfLatest = latest.month.slice(0, 4);
  const yearSnaps = sorted.filter(s => s.month.startsWith(yearOfLatest));
  let ytd = 0;
  for (let i = 0; i < yearSnaps.length; i++) {
    const idxInAll = sorted.indexOf(yearSnaps[i]);
    const p = idxInAll > 0 ? sorted[idxInAll - 1] : null;
    ytd += monthlyPnL(onlyActive(yearSnaps[i]), onlyActive(p));
  }

  // Hero 总资产：拆 ¥ + 整数 + .小数
  renderHeroValue(total);
  document.getElementById('kpi-total-sub').textContent = (isInvestmentView ? '仅投资资产 · ' : '') + '截至 ' + latest.month;
  swapText(document.getElementById('hero-label-text'), isInvestmentView ? '投 资 资 产' : '总 资 产');

  // Hero pill: 月对月变化百分比
  const pill = document.getElementById('kpi-total-pill');
  if (prevTotal && prevTotal > 0) {
    const pct = (total - prevTotal) / prevTotal * 100;
    const isPos = pct >= 0;
    pill.className = 'hero-pill show ' + (isPos ? 'pos' : 'neg');
    pill.textContent = (isPos ? '↑ ' : '↓ ') + Math.abs(pct).toFixed(1) + '%';
  } else {
    pill.classList.remove('show');
  }

  // 颜色变量（收益率模块和图表共用，需在调用前定义）
  const colorInk = getCSSVar('--ink');
  const colorMute = getCSSVar('--ink-3');
  const colorGrid = getCSSVar('--chart-grid');
  const colorAccent = getCSSVar('--accent');
  const colorGreen = getCSSVar('--green');
  const colorRed = getCSSVar('--red');
  const colorBg = getCSSVar('--bg-1');
  const colorTooltipBg = getCSSVar('--tooltip-bg');
  const colorLine = getCSSVar('--sep-strong');

  // 收益率模块（独立 try/catch，图表失败不影响 Hero 统计）
  try {
    renderReturnsModule(sorted, onlyActive);
  } catch (e) {
    console.error('renderReturnsModule failed:', e);
  }

  // Hero 内嵌统计
  renderHeroStatValue('hero-stat-pnl', pnl, true);
  renderHeroStatValue('hero-stat-flow', flow, false);
  renderHeroStatValue('hero-stat-ytd', ytd, true);

  // 较上月对比 (MoM)
  const prevMonthPnl = prev ? monthlyPnL(onlyActive(prev), sorted.length >= 3 ? onlyActive(sorted[sorted.length - 3]) : null) : null;
  const prevMonthFlow = prev ? snapshotFlow(onlyActive(prev)) : null;
  const prevYearSnaps = sorted.filter(s => s.month.startsWith(String(parseInt(yearOfLatest) - 1)));
  let prevYtd = 0;
  for (let i = 0; i < prevYearSnaps.length; i++) {
    const idxInAll = sorted.indexOf(prevYearSnaps[i]);
    const p = idxInAll > 0 ? sorted[idxInAll - 1] : null;
    prevYtd += monthlyPnL(onlyActive(prevYearSnaps[i]), onlyActive(p));
  }
  function renderTrend(elId, current, previous) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (previous === null || previous === undefined || previous === 0) { el.textContent = ''; el.className = 'hero-stat-trend'; return; }
    const change = ((current - previous) / Math.abs(previous)) * 100;
    if (Math.abs(change) < 0.5) { el.textContent = '→ 持平'; el.className = 'hero-stat-trend flat'; }
    else if (change > 0) { el.textContent = '↑ ' + Math.abs(change).toFixed(1) + '% 较上月'; el.className = 'hero-stat-trend up'; }
    else { el.textContent = '↓ ' + Math.abs(change).toFixed(1) + '% 较上月'; el.className = 'hero-stat-trend down'; }
  }
  renderTrend('hero-stat-pnl-trend', pnl, prevMonthPnl);
  renderTrend('hero-stat-flow-trend', flow, prevMonthFlow);
  // YTD: compare to same period last year
  (function(){
    const el = document.getElementById('hero-stat-ytd-trend');
    if (!el) return;
    if (prevYtd === 0) { el.textContent = ''; el.className = 'hero-stat-trend'; return; }
    const change = ((ytd - prevYtd) / Math.abs(prevYtd)) * 100;
    if (Math.abs(change) < 1) { el.textContent = '→ 同比持平'; el.className = 'hero-stat-trend flat'; }
    else if (change > 0) { el.textContent = '↑ ' + Math.abs(change).toFixed(1) + '% 同比'; el.className = 'hero-stat-trend up'; }
    else { el.textContent = '↓ ' + Math.abs(change).toFixed(1) + '% 同比'; el.className = 'hero-stat-trend down'; }
  })();

  // Hero 统计颜色状态
  const pnlState = pnl > 0 ? 'pos' : (pnl < 0 ? 'neg' : '');
  const flowState = flow > 0 ? 'pos' : (flow < 0 ? 'neg' : '');
  const ytdState = ytd > 0 ? 'pos' : (ytd < 0 ? 'neg' : '');

  const pnlEl = document.getElementById('hero-stat-pnl');
  if (pnlEl) pnlEl.className = 'hero-stat-value ' + pnlState;
  const pnlSubEl = document.getElementById('hero-stat-pnl-sub');
  if (pnlSubEl) pnlSubEl.textContent = (prev ? '已剔除 ' + fmtSign(flow) + ' 净流' : '需上月数据') + (isInvestmentView ? '（仅投资）' : '');
  const flowEl = document.getElementById('hero-stat-flow');
  if (flowEl) flowEl.className = 'hero-stat-value ' + flowState;
  const flowSubEl = document.getElementById('hero-stat-flow-sub');
  if (flowSubEl) flowSubEl.textContent = (flow > 0 ? '本月净流入' : (flow < 0 ? '本月净流出' : '无流动')) + (isInvestmentView ? '（仅投资）' : '');
  const ytdEl = document.getElementById('hero-stat-ytd');
  if (ytdEl) ytdEl.className = 'hero-stat-value ' + ytdState;
  const ytdSubEl = document.getElementById('hero-stat-ytd-sub');
  if (ytdSubEl) ytdSubEl.textContent = yearOfLatest + ' 年内 · 仅市场盈亏' + (isInvestmentView ? '（仅投资）' : '');

  Chart.defaults.color = colorMute;
  Chart.defaults.font.family = UI_FONT;
  Chart.defaults.font.size = 12;
  Chart.defaults.borderColor = colorLine;

  const labels = sorted.map(s => s.month);
  const totals = sorted.map(s => snapshotTotal(onlyActive(s)));

  // 总资产曲线 · Percento 风格
  const totalCanvas = document.getElementById('chart-total');
  const totalCtx = totalCanvas.getContext('2d');
  const totalGradient = totalCtx.createLinearGradient(0, 0, 0, 280);
  const accentRgb = hexToRgb(colorAccent);
  totalGradient.addColorStop(0, `rgba(${accentRgb},0.25)`);
  totalGradient.addColorStop(1, `rgba(${accentRgb},0)`);

  const currentTotal = totals[totals.length - 1];
  charts.total = new Chart(totalCanvas, {
    type: 'line',
    data: {
      labels,
      datasets: [{
        data: totals,
        borderColor: colorAccent,
        borderWidth: 3,
        fill: true,
        backgroundColor: totalGradient,
        tension: 0.42,
        pointRadius: 0,
        pointHoverRadius: 6,
        pointBackgroundColor: colorBg,
        pointBorderColor: colorAccent,
        pointBorderWidth: 2,
        pointHoverBorderWidth: 3,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 800, easing: 'easeOutQuart' },
      interaction: { mode: 'index', intersect: false },
      onHover(e, elements) {
        if (elements && elements.length > 0) {
          const v = totals[elements[0].index];
          if (v != null) renderHeroValue(v);
          e.native.target.style.cursor = 'pointer';
        } else {
          e.native.target.style.cursor = 'default';
        }
      },
      onClick(e, elements) {
        if (!elements || elements.length === 0) return;
        const idx = elements[0].index;
        const month = labels[idx];
        if (month) openDrawer('pnl', month);
      },
      plugins: {
        legend: { display: false },
        tooltip: {
          backgroundColor: 'rgba(28,28,30,0.85)',
          titleFont: { size: 12, weight: 'normal' },
          bodyFont: { size: 14, weight: 'bold', family: MONO_FONT },
          padding: 10,
          cornerRadius: 8,
          displayColors: false,
          callbacks: { label: (ctx) => fmt(ctx.parsed.y) },
        },
        // 十字准星线
        crosshair: {
          afterDraw(chart) {
            if (!chart.tooltip || !chart.tooltip._active || !chart.tooltip._active.length) return;
            const ctx = chart.ctx;
            const x = chart.tooltip._active[0].element.x;
            const topY = chart.scales.y.top;
            const bottomY = chart.scales.y.bottom;
            ctx.save();
            ctx.beginPath();
            ctx.moveTo(x, topY);
            ctx.lineTo(x, bottomY);
            ctx.strokeStyle = getCSSVar('--sep-strong') || 'rgba(255,255,255,0.08)';
            ctx.lineWidth = 1;
            ctx.setLineDash([4, 4]);
            ctx.stroke();
            ctx.restore();
          },
        },
      },
      scales: {
        x: {
          display: true,
          grid: { display: false, drawBorder: false },
          border: { display: false },
          ticks: { color: colorMute, font: { size: 11 }, maxRotation: 0, autoSkip: true, maxTicksLimit: 6 },
        },
        y: {
          display: true,
          position: 'right',
          grid: { display: false, drawBorder: false },
          border: { display: false },
          ticks: {
            color: colorMute,
            font: { size: 11, family: MONO_FONT },
            maxTicksLimit: 5,
            padding: 8,
            callback: (v) => '¥' + (v / 10000).toFixed(0) + '万',
          },
        },
      },
    },
  });
  // 鼠标离开图表时恢复当前总额
  totalCanvas.addEventListener('mouseleave', () => renderHeroValue(currentTotal));
  // 饼图（仅活跃账户）
  const groupTotals = {};
  const pieGroupMap = {};
  const activeLatest = onlyActive(latest);
  for (const a of state.accounts) {
    if (a.archived) continue;
    const e = activeLatest.entries[a.id];
    if (!e || !e.balance) continue;
    const bal = Number(e.balance) || 0;
    groupTotals[a.group] = (groupTotals[a.group] || 0) + bal;
    if (!pieGroupMap[a.group]) pieGroupMap[a.group] = [];
    pieGroupMap[a.group].push({ name: a.name, balance: bal, type: a.type });
  }
  const pieLabels = Object.keys(groupTotals);
  const pieData = pieLabels.map(l => groupTotals[l]);
  // 动态继承 CSS 变量，深浅色主题一致
  const palette = [
    getCSSVar('--accent') || '#0071e3',
    getCSSVar('--green') || '#34c759',
    getCSSVar('--yellow') || '#ff9500',
    getCSSVar('--red') || '#ff3b30',
    getCSSVar('--accent-purple') || '#5e6ad2',
    '#8b5cf6', '#38bdf8', '#f59e0b'
  ];

  charts.pie = new Chart(document.getElementById('chart-pie'), {
    type: 'doughnut',
    data: {
      labels: pieLabels,
      datasets: [{
        data: pieData,
        backgroundColor: pieLabels.map((_, i) => palette[i % palette.length]),
        borderColor: colorBg,
        borderWidth: 3,
        hoverOffset: 8,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      cutout: '68%',
      onClick: (e, els) => {
        if (els.length === 0) return;
        const idx = els[0].index;
        const group = pieLabels[idx];
        const accs = pieGroupMap[group] || [];
        accs.sort((a, b) => Math.abs(b.balance) - Math.abs(a.balance));
        openPieDrilldown(group, accs, groupTotals[group]);
      },
      animation: {
        animateRotate: true,
        duration: 900,
        easing: 'easeOutQuart',
      },
      plugins: {
        legend: {
          position: 'bottom',
          labels: {
            padding: 16,
            font: { size: 12, family: UI_FONT },
            boxWidth: 10,
            boxHeight: 10,
            usePointStyle: true,
            pointStyle: 'circle',
          },
        },
        tooltip: {
          backgroundColor: colorTooltipBg,
          borderColor: colorLine,
          borderWidth: 1,
          titleColor: colorInk,
          bodyColor: colorInk,
          padding: 14,
          cornerRadius: 12,
          titleFont: { size: 13, weight: '600' },
          bodyFont: { size: 13 },
          callbacks: {
            label: (ctx) => {
              const tot = ctx.dataset.data.reduce((a, b) => a + b, 0);
              const pct = tot ? (ctx.parsed / tot * 100).toFixed(1) : 0;
              return ' ' + ctx.label + '  ' + fmt(ctx.parsed) + '  ' + pct + '%';
            },
          },
        },
      },
    },
  });

  renderTargetAllocation();

  // 盈亏柱图（仅活跃账户）
  const pnls = sorted.map((s, i) => monthlyPnL(onlyActive(s), i > 0 ? onlyActive(sorted[i - 1]) : null));
  const flows = sorted.map(s => snapshotFlow(onlyActive(s)));
  const greenRgb = hexToRgb(colorGreen);
  const redRgb = hexToRgb(colorRed);
  const greyRgb = '142,142,147';

  charts.pnl = new Chart(document.getElementById('chart-pnl'), {
    type: 'bar',
    data: {
      labels,
      datasets: [
        {
          label: '市场盈亏',
          data: pnls,
          backgroundColor: pnls.map(v => v >= 0 ? `rgba(${greenRgb},0.85)` : `rgba(${redRgb},0.85)`),
          hoverBackgroundColor: pnls.map(v => v >= 0 ? `rgba(${greenRgb},1)` : `rgba(${redRgb},1)`),
          borderRadius: 4,
          borderSkipped: false,
          barPercentage: 0.6,
          categoryPercentage: 0.8,
          minBarLength: 3,
        },
        {
          label: '净入金',
          data: flows,
          backgroundColor: `rgba(${greyRgb},0.35)`,
          hoverBackgroundColor: `rgba(${greyRgb},0.55)`,
          borderRadius: 4,
          borderSkipped: false,
          barPercentage: 0.6,
          categoryPercentage: 0.8,
          minBarLength: 3,
        },
      ],
    },
    plugins: [{
      id: 'barLabel',
      afterDraw(chart) {
        const ctx = chart.ctx;
        const meta = chart.getDatasetMeta(0);
        if (!meta || !meta.data) return;
        ctx.save();
        ctx.font = '11px ' + MONO_FONT;
        ctx.textAlign = 'center';
        meta.data.forEach((bar, i) => {
          const v = chart.data.datasets[0].data[i];
          if (v == null || isNaN(v) || v === 0) return;
          const label = v >= 0 ? '+' + (v / 10000).toFixed(1) + '万' : (v / 10000).toFixed(1) + '万';
          const y = v >= 0 ? bar.y - 6 : bar.y + 14;
          ctx.fillStyle = v >= 0 ? colorGreen : colorRed;
          ctx.fillText(label, bar.x, y);
        });
        ctx.restore();
      },
    }],
    options: {
      responsive: true,
      maintainAspectRatio: false,
      animation: { duration: 800, easing: 'easeOutQuart' },
      interaction: { mode: 'index', intersect: false },
      onClick: (evt, elements) => {
        if (!elements || elements.length === 0) return;
        const idx = elements[0].index;
        const month = labels[idx];
        if (month) openDrawer('pnl', month);
      },
      onHover: (evt, elements) => {
        evt.native.target.style.cursor = elements.length ? 'pointer' : 'default';
      },
      plugins: {
        legend: {
          position: 'top',
          align: 'end',
          labels: {
            boxWidth: 10,
            boxHeight: 10,
            padding: 16,
            font: { size: 12, family: UI_FONT },
            usePointStyle: true,
            pointStyle: 'circle',
          },
        },
        tooltip: {
          backgroundColor: colorTooltipBg,
          borderColor: colorLine,
          borderWidth: 1,
          titleColor: colorInk,
          bodyColor: colorInk,
          padding: 14,
          cornerRadius: 12,
          titleFont: { size: 13, weight: '600' },
          bodyFont: { size: 13 },
          callbacks: { label: (ctx) => ' ' + ctx.dataset.label + ': ' + fmtSign(ctx.parsed.y) },
        },
      },
      scales: {
        x: {
          stacked: true,
          grid: { display: false },
          border: { display: false },
          ticks: { color: colorMute },
        },
        y: {
          stacked: true,
          grid: { color: colorGrid },
          border: { display: false },
          ticks: { color: colorMute, callback: (v) => (v >= 0 ? '+' : '') + (v / 10000).toFixed(1) + '万' },
        },
      },
    },
  });


}

// ============================================================
// 录入
// ============================================================
const DRAFT_KEY_PREFIX = 'asset-ledger-draft-';
function draftKey(month) { return DRAFT_KEY_PREFIX + month; }

function loadDraft(month) {
  const snap = state.snapshots.find(s => s.month === month);
  const draft = {};
  for (const a of state.accounts) {
    if (snap && snap.entries[a.id]) {
      const stored = snap.entries[a.id];
      const displayBalance = stored.balance === '' || stored.balance === null || stored.balance === undefined
        ? ''
        : Math.abs(Number(stored.balance));
      draft[a.id] = {
        balance: displayBalance === '' ? '' : displayBalance,
        flow: stored.flow === '' || stored.flow === null || stored.flow === undefined ? '' : stored.flow,
      };
    } else {
      draft[a.id] = { balance: '', flow: '' };
    }
  }
  // 合并 localStorage 中未保存的草稿（比如浏览器意外刷新）
  try {
    const persisted = localStorage.getItem(draftKey(month));
    if (persisted) {
      const pd = JSON.parse(persisted);
      if (pd && typeof pd === 'object') {
        for (const [id, vals] of Object.entries(pd)) {
          if (draft[id]) {
            if (vals.balance !== undefined) draft[id].balance = vals.balance;
            if (vals.flow !== undefined) draft[id].flow = vals.flow;
          }
        }
      }
    }
  } catch {}
  return draft;
}

let draftSaveTimer = null;
// monthKey 参数通过闭包锁定，防止切月份时草稿错位串台
function autoSaveDraft(monthKey) {
  if (draftSaveTimer) clearTimeout(draftSaveTimer);
  const snapshot = JSON.stringify(state.editingDraft);
  draftSaveTimer = setTimeout(() => {
    try {
      localStorage.setItem(draftKey(monthKey), snapshot);
    } catch {}
  }, 500);
}
function clearPersistedDraft(month) {
  try { localStorage.removeItem(draftKey(month)); } catch {}
}

function renderEntry() {
  const monthInput = document.getElementById('entry-month');
  if (!state.editingMonth) state.editingMonth = ymNow();
  monthInput.value = state.editingMonth;
  state.editingDraft = loadDraft(state.editingMonth);

  // 自动预填：新月份且所有账户为空时，用最近快照数据填充
  const currentSnap = state.snapshots.find(s => s.month === state.editingMonth);
  if (!currentSnap && state.snapshots.length > 0) {
    const allEmpty = Object.values(state.editingDraft).every(d => d.balance === '' && d.flow === '');
    if (allEmpty) {
      const sorted = getSortedSnapshots();
      const recent = sorted[sorted.length - 1];
      for (const a of state.accounts) {
        const entry = recent.entries[a.id];
        if (entry && entry.balance !== '' && entry.balance !== null && entry.balance !== undefined) {
          if (state.editingDraft[a.id]) {
            state.editingDraft[a.id].balance = Math.abs(Number(entry.balance));
          }
        }
      }
    }
  }

  // Show/hide archive toggle based on whether any account is archived
  const hasArchived = state.accounts.some(a => a.archived);
  document.getElementById('archive-toggle-wrap').style.display = hasArchived ? '' : 'none';
  const showArchived = document.getElementById('show-archived').checked;

  const grouped = groupAccounts();
  const prevMonth = ymPrev(state.editingMonth);
  const prevSnap = state.snapshots.find(s => s.month === prevMonth);
  const baseSnap = currentSnap || prevSnap;
  const container = document.getElementById('entry-groups');
  container.innerHTML = '';

  if (Object.keys(grouped).length === 0) {
    container.innerHTML = '<div class="empty"><div class="glyph">＋</div><p>尚无分组与账户</p><div class="hint">点击下方「新增分组」创建第一个资产分组</div></div>';
    return;
  }

  for (const group of getAllGroups()) {
    const accs = grouped[group] || [];
    // Sort: 活跃账户在上 → 归档在下，组内按 order 排序
    accs.sort((a, b) => {
      if (a.archived && !b.archived) return 1;
      if (!a.archived && b.archived) return -1;
      return (a.order || 0) - (b.order || 0);
    });

    const section = document.createElement('div');
    section.className = 'group-section';
    section.dataset.group = group;

    const titleBar = document.createElement('div');
    titleBar.className = 'group-title-bar';
    titleBar.innerHTML = `
      <h4>${escapeHtml(group)}</h4>
      <div class="group-actions">
        <button class="icon-btn primary" data-action="add-account" data-group="${escapeHtml(group)}">＋ 加账户</button>
        <button class="icon-btn" data-action="rename-group" data-group="${escapeHtml(group)}">重命名</button>
        <button class="icon-btn danger" data-action="delete-group" data-group="${escapeHtml(group)}">删除</button>
      </div>
    `;
    section.appendChild(titleBar);

    const header = document.createElement('div');
    header.className = 'entry-row header-row';
    header.innerHTML = `
      <div>账户</div>
      <div>月末余额</div>
      <div>本月净入金</div>
      <div>较上月</div>
      <div></div>
    `;
    section.appendChild(header);

    if (accs.length === 0) {
      const empty = document.createElement('div');
      empty.style.padding = '14px 0';
      empty.style.color = 'var(--ink-3)';
      empty.style.fontSize = '14px';
      empty.textContent = '此分组下尚无账户';
      section.appendChild(empty);
    }

    for (const a of accs) {
      if (a.archived && !showArchived) continue;
      const row = document.createElement('div');
      row.className = 'entry-row' + (a.archived ? ' archived' : '');
      const draft = state.editingDraft[a.id];
      // 上月余额（存的是有符号值，显示用绝对值）
      const baseBalSigned = baseSnap && baseSnap.entries[a.id] ? Number(baseSnap.entries[a.id].balance) || 0 : null;
      const baseBalAbs = baseBalSigned !== null ? Math.abs(baseBalSigned) : null;
      // 当前输入（用户视角是绝对值）
      const currBalAbs = draft.balance === '' ? null : Number(draft.balance);
      // 对比基准快照的差额
      const delta = (baseBalAbs !== null && currBalAbs !== null) ? (currBalAbs - baseBalAbs) : null;
      // 是否「沿用」状态：当前未填且对比基准有值
      const isCarryOver = draft.balance === '' && baseBalAbs !== null;

      const balPlaceholder = baseBalAbs !== null ? baseBalAbs.toLocaleString('zh-CN') : '0';
      const liabilityBadge = a.type === 'liability' ? '<span class="type-badge">负债</span>' : '';
      const carryBadge = isCarryOver ? '<span class="carry-badge">沿用</span>' : '';

      row.innerHTML = `
        <div class="name" style="cursor:pointer" data-acc-trend="${a.id}" title="查看余额趋势">${escapeHtml(a.name)}<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="opacity:0.35;flex-shrink:0;margin-left:2px"><polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/></svg>${liabilityBadge}<span class="tag-badge ${a.tag || 'cash'}">${({investment:'投资',credit:'债权', 'long-term':'长期', cash:'流动',liability:'负债'})[a.tag||'cash']}</span>${carryBadge}</div>
        <input type="text" inputmode="decimal" pattern="[0-9]*" data-acc="${a.id}" data-field="balance" value="${draft.balance}" placeholder="${balPlaceholder}" class="${isCarryOver ? 'is-carry' : ''}">
        <input type="text" inputmode="decimal" pattern="[0-9]*" data-acc="${a.id}" data-field="flow" value="${draft.flow}" placeholder="0">
        <div class="delta" data-delta="${a.id}">${delta !== null ? (delta >= 0 ? '+' : '') + Math.round(delta).toLocaleString('zh-CN') : '—'}</div>
        <div class="row-actions">
          <button class="move-btn" title="上移" data-action="move-account" data-acc="${a.id}" data-dir="up">↑</button>
          <button class="move-btn" title="下移" data-action="move-account" data-acc="${a.id}" data-dir="down">↓</button>
          <button class="icon-btn" data-action="edit-account" data-acc="${a.id}">编辑</button>
        </div>
      `;
      section.appendChild(row);
    }

    container.appendChild(section);
  }

  const debouncedBalanceUpdate = debounce((accId, value, target) => {
    const baseBalSigned = baseSnap && baseSnap.entries[accId] ? Number(baseSnap.entries[accId].balance) || 0 : null;
    const baseBalAbs = baseBalSigned !== null ? Math.abs(baseBalSigned) : null;
    const v = value === '' ? null : Number(value);
    target.classList.toggle('is-carry', v === null && baseBalAbs !== null);
    const row = target.closest('.entry-row');
    if (row) {
      const existingBadge = row.querySelector('.carry-badge');
      if (v !== null && existingBadge) existingBadge.remove();
      else if (v === null && baseBalAbs !== null && !existingBadge) {
        const nameDiv = row.querySelector('.name');
        if (nameDiv) {
          const span = document.createElement('span');
          span.className = 'carry-badge';
          span.textContent = '沿用';
          nameDiv.appendChild(span);
        }
      }
    }
    const cell = container.querySelector(`[data-delta="${accId}"]`);
    if (cell) {
      if (baseBalAbs !== null && v !== null) {
        const d = v - baseBalAbs;
        cell.textContent = (d >= 0 ? '+' : '') + Math.round(d).toLocaleString('zh-CN');
      } else cell.textContent = '—';
    }
  }, 250);

  // 事件委托：替代循环绑定，防止内存泄漏并确保动态添加的输入框也生效
  container.oninput = (e) => {
    if (e.target.tagName === 'INPUT' && e.target.hasAttribute('data-acc')) {
      const accId = e.target.dataset.acc;
      const field = e.target.dataset.field;
      state.editingDraft[accId][field] = e.target.value;
      setEntryDirty(true);
      autoSaveDraft(state.editingMonth);
      if (field === 'balance') {
        debouncedBalanceUpdate(accId, e.target.value, e.target);
      }
    }
  };

  const tryEvalFormula = (input) => {
    const v = input.value.trim();
    if (v[0] !== '=') return false;
    const result = evalFormula(v);
    if (result === null) return false;
    input.value = result;
    const accId = input.dataset.acc;
    const field = input.dataset.field;
    state.editingDraft[accId][field] = result;
    setEntryDirty(true);
    autoSaveDraft(state.editingMonth);
    if (field === 'balance') debouncedBalanceUpdate(accId, result, input);
    return true;
  };

  container.addEventListener('focusout', (e) => {
    if (e.target.tagName === 'INPUT' && e.target.hasAttribute('data-acc')) {
      tryEvalFormula(e.target);
    }
  });

  // Enter 跳转下一个输入框
  container.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && !e.shiftKey && !e.metaKey && !e.ctrlKey && e.target.tagName === 'INPUT') {
      tryEvalFormula(e.target);
      const inputs = [...container.querySelectorAll('.entry-row:not(.header-row) input')];
      const idx = inputs.indexOf(e.target);
      if (idx >= 0 && idx < inputs.length - 1) {
        e.preventDefault();
        inputs[idx + 1].focus();
      }
    }
  });

  document.getElementById('group-list').innerHTML = getAllGroups().map(g => `<option value="${escapeHtml(g)}">`).join('');
  setEntryDirty(false);
}

function handleEntryAction(action, dataset) {
  if (action === 'add-account') openAccountModal(null, dataset.group);
  else if (action === 'edit-account') openAccountModal(dataset.acc, null);
  else if (action === 'rename-group') openGroupModal(dataset.group);
  else if (action === 'delete-group') deleteGroup(dataset.group);
  else if (action === 'move-account') moveAccount(dataset.acc, dataset.dir);
}

async function moveAccount(accId, dir) {
  const acc = state.accounts.find(a => a.id === accId);
  if (!acc) return;
  const groupAccs = state.accounts
    .filter(a => a.group === acc.group)
    .sort((a, b) => (a.order || 0) - (b.order || 0));
  const idx = groupAccs.indexOf(acc);
  if (dir === 'up' && idx > 0) {
    const above = groupAccs[idx - 1];
    [acc.order, above.order] = [above.order, acc.order];
  } else if (dir === 'down' && idx < groupAccs.length - 1) {
    const below = groupAccs[idx + 1];
    [acc.order, below.order] = [below.order, acc.order];
  } else return;
  renderEntry();
  await persistVault();
  showToast('已调整顺序');
}

function setEntryDirty(dirty) {
  state.entryDirty = dirty;
  const btn = document.querySelector('[data-page="entry"]');
  if (btn) btn.classList.toggle('dirty', dirty);
}

function checkAnomalies(entries, prevMonthSnap) {
  if (!prevMonthSnap) return [];
  const anomalies = [];
  for (const a of state.accounts) {
    const newEntry = entries[a.id];
    const oldEntry = prevMonthSnap.entries[a.id];
    if (!newEntry || !oldEntry || oldEntry.balance === null || oldEntry.balance === undefined || oldEntry.balance === '') continue;
    const newBal = Math.abs(Number(newEntry.balance) || 0);
    const oldBal = Math.abs(Number(oldEntry.balance) || 0);
    let change;
    if (oldBal === 0) {
      if (newBal === 0) continue;
      change = 1; // 0→非0 视为 100% 变化，触发提醒
    } else {
      change = (newBal - oldBal) / oldBal;
    }
    if (Math.abs(change) > state.anomalyThreshold) {
      anomalies.push({ account: a, prevBal: oldBal, currBal: newBal, change });
    }
  }
  return anomalies.sort((x, y) => Math.abs(y.change) - Math.abs(x.change));
}

let pendingAnomalySave = null;
document.getElementById('anomaly-cancel').addEventListener('click', () => {
  document.getElementById('anomaly-modal').classList.remove('active');
  pendingAnomalySave = null;
  // 恢复草稿：清除 localStorage 并从快照重新加载，避免异常修改残留
  clearPersistedDraft(state.editingMonth);
  state.editingDraft = loadDraft(state.editingMonth);
  renderEntry();
});
document.getElementById('anomaly-confirm').addEventListener('click', async () => {
  document.getElementById('anomaly-modal').classList.remove('active');
  if (pendingAnomalySave) await pendingAnomalySave();
  pendingAnomalySave = null;
});

// Cmd/Ctrl + Enter 保存
document.addEventListener('keydown', (e) => {
  if ((e.metaKey || e.ctrlKey) && e.key === 'Enter' && state.current === 'entry') {
    e.preventDefault();
    document.getElementById('entry-save').click();
  }
});

document.getElementById('entry-month').addEventListener('change', (e) => {
  state.editingMonth = normalizeMonth(e.target.value);
  e.target.value = state.editingMonth;
  renderEntry();
});
document.getElementById('entry-month-prev').addEventListener('click', () => {
  state.editingMonth = ymPrev(state.editingMonth);
  document.getElementById('entry-month').value = state.editingMonth;
  renderEntry();
});
document.getElementById('entry-month-next').addEventListener('click', () => {
  state.editingMonth = ymNext(state.editingMonth);
  document.getElementById('entry-month').value = state.editingMonth;
  renderEntry();
});
document.getElementById('show-archived').addEventListener('change', () => renderEntry());
document.getElementById('refresh-btn').addEventListener('click', refreshFromCloud);
document.getElementById('empty-start-btn').addEventListener('click', () => navTo('entry'));
document.getElementById('hero-label').addEventListener('click', () => openDrawer('assets'));
// 录入页事件委托：账户操作按钮 + 趋势图点击
document.getElementById('entry-groups').addEventListener('click', (e) => {
  const actionBtn = e.target.closest('[data-action]');
  if (actionBtn) {
    handleEntryAction(actionBtn.dataset.action, actionBtn.dataset);
    return;
  }
  const trendEl = e.target.closest('[data-acc-trend]');
  if (trendEl) {
    e.stopPropagation();
    openAccountTrend(trendEl.dataset.accTrend);
  }
});

document.getElementById('entry-prefill').addEventListener('click', () => {
  const prev = state.snapshots.find(s => s.month === ymPrev(state.editingMonth));
  if (!prev) { showToast('上月无数据', 'error'); return; }
  for (const a of state.accounts) {
    if (prev.entries[a.id] && prev.entries[a.id].balance !== '' && prev.entries[a.id].balance !== null) {
      // 显示给用户的是绝对值
      state.editingDraft[a.id] = {
        balance: Math.abs(Number(prev.entries[a.id].balance) || 0),
        flow: 0,
      };
    }
  }
  renderEntry();
  showToast('已填入上月余额');
});
document.getElementById('entry-cancel').addEventListener('click', () => {
  clearPersistedDraft(state.editingMonth);
  state.editingDraft = loadDraft(state.editingMonth);
  renderEntry();
  showToast('已恢复');
});
document.getElementById('entry-save').addEventListener('click', async () => {
  const btn = document.getElementById('entry-save');
  btn.disabled = true;
  btn.style.opacity = '0.7';
  btn.style.pointerEvents = 'none';
  const origHTML = btn.innerHTML;
  btn.innerHTML = '<span class="spinner"></span>保存中…';

  try {
    const currentMonthSnap = state.snapshots.find(s => s.month === state.editingMonth);
    const prevMonthSnap = state.snapshots.find(s => s.month === ymPrev(state.editingMonth));
    const baseSnap = currentMonthSnap || prevMonthSnap;
    const entries = {};
    for (const a of state.accounts) {
      const d = state.editingDraft[a.id];
      let balance;
      if (d.balance === '' || d.balance === null || d.balance === undefined) {
        if (baseSnap && baseSnap.entries[a.id] && baseSnap.entries[a.id].balance !== '' && baseSnap.entries[a.id].balance !== null && baseSnap.entries[a.id].balance !== undefined) {
          balance = Number(baseSnap.entries[a.id].balance) || 0;
        } else {
          balance = 0;
        }
      } else {
        const absVal = Math.abs(Number(d.balance) || 0);
        balance = a.type === 'liability' ? -absVal : absVal;
      }
      const flow = d.flow === '' || d.flow === null || d.flow === undefined ? 0 : Number(d.flow);
      entries[a.id] = { balance, flow };
    }
    const monthKey = normalizeMonth(state.editingMonth);
    state.editingMonth = monthKey;
    const snap = { month: monthKey, entries, updatedAt: Date.now() };

    // 重大变化检查：本月有快照则对比本月，否则对比上月
    const anomalies = checkAnomalies(entries, baseSnap);

    const doSave = async () => {
      state.snapshots = state.snapshots.filter(s => s.month !== monthKey);
      state.snapshots.push(snap);
      await persistVault();
      clearPersistedDraft(state.editingMonth);
      showToast(state.editingMonth + ' 快照已保存');
      renderEntry();
    };

    if (anomalies.length > 0) {
      document.getElementById('anomaly-threshold-pct').textContent = Math.round(state.anomalyThreshold * 100) + '%';
      document.getElementById('anomaly-list').innerHTML = anomalies.map(x => {
        const dir = x.change > 0 ? '↑' : '↓';
        const cls = x.change > 0 ? 'pos' : 'neg';
        return '<div style="display:flex;align-items:center;gap:8px;padding:8px 0;border-bottom:0.5px solid var(--sep);font-size:13px">' +
          '<span style="flex:1;font-weight:500">' + escapeHtml(x.account.name) + '</span>' +
          '<span style="font-family:var(--font-mono);font-size:12px;color:var(--ink-4)">' + fmt(x.prevBal) + '</span>' +
          '<span style="color:var(--ink-4)">→</span>' +
          '<span style="font-family:var(--font-mono);font-size:12px">' + fmt(x.currBal) + '</span>' +
          '<span class="' + cls + '" style="font-family:var(--font-mono);font-size:12px;font-weight:600;min-width:56px;text-align:right">' + dir + ' ' + Math.abs(x.change * 100).toFixed(1) + '%</span>' +
          '</div>';
      }).join('');
      pendingAnomalySave = async () => {
        btn.disabled = true; btn.style.opacity = '0.7'; btn.style.pointerEvents = 'none';
        btn.innerHTML = '<span class="spinner"></span>保存中…';
        try { await doSave(); } catch (err) {
          console.error('保存失败:', err);
          showToast('保存失败：' + (err.message || '未知错误') + '。请检查网络，并导出加密备份。', 'error');
        } finally {
          btn.disabled = false; btn.style.opacity = '1'; btn.style.pointerEvents = 'auto';
          btn.innerHTML = origHTML;
        }
      };
      btn.disabled = false; btn.style.opacity = '1'; btn.style.pointerEvents = 'auto';
      btn.innerHTML = origHTML;
      document.getElementById('anomaly-modal').classList.add('active');
      return;
    }

    state.snapshots = state.snapshots.filter(s => s.month !== monthKey);
    state.snapshots.push(snap);
    await persistVault();
    clearPersistedDraft(state.editingMonth);
    showToast(state.editingMonth + ' 快照已保存');
    renderEntry();
  } catch (err) {
    console.error('保存失败:', err);
    showToast('保存失败：' + (err.message || '未知错误') + '。请检查网络，并导出加密备份。', 'error');
  } finally {
    btn.disabled = false;
    btn.style.opacity = '1';
    btn.style.pointerEvents = 'auto';
    btn.innerHTML = origHTML;
  }
});

// ============================================================
// 账户管理
// ============================================================
function openAccountModal(id, defaultGroup) {
  state.editAccId = id || null;
  document.getElementById('account-modal-title').textContent = id ? '编辑账户' : '新增账户';
  if (id) {
    const a = state.accounts.find(x => x.id === id);
    document.getElementById('acc-name').value = a.name;
    document.getElementById('acc-group').value = a.group;
    document.getElementById('acc-type').value = a.type;
    document.getElementById('acc-tag').value = a.tag || 'cash';
  } else {
    document.getElementById('acc-name').value = '';
    document.getElementById('acc-group').value = defaultGroup || (getAllGroups()[0] || '');
    document.getElementById('acc-type').value = 'asset';
    document.getElementById('acc-tag').value = 'investment';
  }
  document.getElementById('group-list').innerHTML = getAllGroups().map(g => `<option value="${escapeHtml(g)}">`).join('');
  document.getElementById('account-modal').classList.add('active');
  setTimeout(() => document.getElementById('acc-name').focus(), 50);
}
document.getElementById('acc-cancel').addEventListener('click', () => {
  document.getElementById('account-modal').classList.remove('active');
});
document.getElementById('acc-save').addEventListener('click', async () => {
  const name = document.getElementById('acc-name').value.trim();
  const group = document.getElementById('acc-group').value.trim();
  const type = document.getElementById('acc-type').value;
  if (!name) { showToast('账户名不能为空', 'error'); return; }
  if (!group) { showToast('分组不能为空', 'error'); return; }

  const tag = document.getElementById('acc-tag').value;
  if (state.editAccId) {
    const acc = state.accounts.find(a => a.id === state.editAccId);
    acc.name = name; acc.group = group; acc.type = type; acc.tag = tag;
  } else {
    state.accounts.push({
      id: 'a' + Date.now() + '-' + Math.random().toString(36).slice(2, 7),
      name, group, type, tag, order: state.accounts.length + 1,
    });
  }
  if (!state.groupOrder.includes(group)) state.groupOrder.push(group);

  await persistVault();
  document.getElementById('account-modal').classList.remove('active');
  renderEntry();
  showToast('已保存');
});

// 账户弹窗按钮显隐
(function initAccModalButtons() {
  const modal = document.getElementById('account-modal');
  const delBtn = document.getElementById('acc-delete');
  const archBtn = document.getElementById('acc-archive');

  const obs = new MutationObserver(() => {
    const isEdit = !!state.editAccId;
    delBtn.style.display = isEdit ? '' : 'none';
    archBtn.style.display = isEdit ? '' : 'none';
    if (isEdit) {
      const acc = state.accounts.find(a => a.id === state.editAccId);
      archBtn.textContent = acc && acc.archived ? '取消归档' : '归档';
    }
  });
  obs.observe(modal, { attributes: true, attributeFilter: ['class'] });
})();
document.getElementById('acc-delete').addEventListener('click', async () => {
  if (!state.editAccId) return;
  if (!confirm('确认删除此账户？历史快照中该账户的数据将不再显示。')) return;
  state.accounts = state.accounts.filter(a => a.id !== state.editAccId);
  await persistVault();
  document.getElementById('account-modal').classList.remove('active');
  renderEntry();
  showToast('已删除');
});
document.getElementById('acc-archive').addEventListener('click', async () => {
  if (!state.editAccId) return;
  const acc = state.accounts.find(a => a.id === state.editAccId);
  if (!acc) return;
  acc.archived = !acc.archived;
  await persistVault();
  document.getElementById('account-modal').classList.remove('active');
  showToast(acc.archived ? '已归档（概览中隐藏）' : '已取消归档');
});

// ============================================================
// 分组管理
// ============================================================
function openGroupModal(originalName) {
  state.editGroupOriginal = originalName || null;
  document.getElementById('group-modal-title').textContent = originalName ? '重命名分组' : '新增分组';
  document.getElementById('group-name-input').value = originalName || '';
  document.getElementById('group-modal').classList.add('active');
  setTimeout(() => document.getElementById('group-name-input').focus(), 50);
}
document.getElementById('add-group-btn').addEventListener('click', () => openGroupModal(null));
document.getElementById('group-cancel').addEventListener('click', () => {
  document.getElementById('group-modal').classList.remove('active');
});
document.getElementById('group-save').addEventListener('click', async () => {
  const newName = document.getElementById('group-name-input').value.trim();
  if (!newName) { showToast('分组名不能为空', 'error'); return; }
  const existing = getAllGroups();
  if (state.editGroupOriginal) {
    if (newName === state.editGroupOriginal) {
      document.getElementById('group-modal').classList.remove('active');
      return;
    }
    if (existing.includes(newName)) { showToast('该名称已存在', 'error'); return; }
    for (const a of state.accounts) {
      if (a.group === state.editGroupOriginal) a.group = newName;
    }
    const idx = state.groupOrder.indexOf(state.editGroupOriginal);
    if (idx >= 0) state.groupOrder[idx] = newName;
    else state.groupOrder.push(newName);
    // 迁移目标配置中的 key
    if (state.targetAllocation[state.editGroupOriginal] !== undefined) {
      state.targetAllocation[newName] = state.targetAllocation[state.editGroupOriginal];
      delete state.targetAllocation[state.editGroupOriginal];
    }
  } else {
    if (existing.includes(newName)) { showToast('该分组已存在', 'error'); return; }
    state.groupOrder.push(newName);
  }
  await persistVault();
  document.getElementById('group-modal').classList.remove('active');
  renderEntry();
  showToast('已保存');
});
async function deleteGroup(group) {
  const accsInGroup = state.accounts.filter(a => a.group === group);
  if (accsInGroup.length > 0) {
    showToast('请先删除或转移此分组下的账户', 'error');
    return;
  }
  if (!confirm(`确认删除分组「${group}」？`)) return;
  state.groupOrder = state.groupOrder.filter(g => g !== group);
  if (state.targetAllocation[group]) delete state.targetAllocation[group];
  await persistVault();
  renderEntry();
  showToast('已删除分组');
}

// ============================================================
// 目标配置
// ============================================================
function openTargetModal() {
  const groups = getAllGroups();
  const inputs = document.getElementById('target-inputs');
  let total = 0;
  inputs.innerHTML = groups.map(g => {
    const pct = state.targetAllocation[g] || 0;
    total += pct;
    return '<div style="display:flex;align-items:center;gap:10px;margin-bottom:8px">' +
      '<span style="flex:0 0 100px;font-size:13px;font-weight:500">' + escapeHtml(g) + '</span>' +
      '<input type="number" min="0" max="100" value="' + pct + '" data-target-group="' + escapeHtml(g) + '" style="width:70px;text-align:right;font-size:13px;padding:6px 10px">' +
      '<span style="font-size:12px;color:var(--ink-4)">%</span>' +
      '</div>';
  }).join('');
  document.getElementById('target-total-pct').textContent = total;

  inputs.querySelectorAll('input').forEach(inp => {
    inp.addEventListener('input', () => {
      let sum = 0;
      inputs.querySelectorAll('input').forEach(i => sum += (Number(i.value) || 0));
      document.getElementById('target-total-pct').textContent = sum;
      document.getElementById('target-total-pct').style.color = sum === 100 ? 'var(--green)' : 'var(--red)';
    });
  });

  document.getElementById('target-modal').classList.add('active');
  setTimeout(() => inputs.querySelector('input')?.focus(), 50);
}
document.getElementById('open-target-config').addEventListener('click', openTargetModal);
document.getElementById('target-cancel').addEventListener('click', () => {
  document.getElementById('target-modal').classList.remove('active');
});
document.getElementById('target-save').addEventListener('click', async () => {
  const inputs = document.getElementById('target-inputs').querySelectorAll('input');
  const alloc = {};
  let sum = 0;
  for (const inp of inputs) {
    const v = Number(inp.value) || 0;
    alloc[inp.dataset.targetGroup] = v;
    sum += v;
  }
  if (sum !== 100) { showToast('占比总和需为 100%，当前为 ' + sum + '%', 'error'); return; }
  state.targetAllocation = alloc;
  await persistVault();
  document.getElementById('target-modal').classList.remove('active');
  renderDashboard();
  showToast('目标配置已保存');
});

function renderTargetAllocation() {
  const el = document.getElementById('target-deviation');
  if (!el) return;
  const groups = getAllGroups();
  const hasTarget = Object.keys(state.targetAllocation).some(g => state.targetAllocation[g] > 0);
  if (!hasTarget) {
    el.innerHTML = '<div style="font-size:12px;color:var(--ink-4);text-align:center;padding:8px 0">点击「⚙ 目标」设置各分组的理想占比</div>';
    return;
  }

  const sorted = getSortedSnapshots();
  if (sorted.length === 0) { el.innerHTML = ''; return; }
  const latest = sorted[sorted.length - 1];
  // 计算当前实际占比
  let total = 0;
  const current = {};
  for (const g of groups) {
    current[g] = 0;
    for (const a of state.accounts) {
      if (a.archived || a.group !== g) continue;
      const e = latest.entries[a.id];
      if (e && e.balance) current[g] += Math.abs(Number(e.balance)) || 0;
    }
    total += current[g];
  }

  let html = '<div style="font-size:12px;font-weight:600;color:var(--ink-3);margin-bottom:8px">当前 vs 目标占比</div>';
  for (const g of groups) {
    const curPct = total > 0 ? (current[g] / total * 100) : 0;
    const targetPct = state.targetAllocation[g] || 0;
    if (targetPct === 0) continue;
    const diff = Math.abs(curPct - targetPct);
    const deviated = diff > 5;
    html += '<div class="alloc-row' + (deviated ? ' deviated' : '') + '">' +
      '<span class="label">' + escapeHtml(g) + (deviated ? ' ⚠' : '') + '</span>' +
      '<div class="bar-wrap">' +
        '<span class="bar-fill current" style="width:' + curPct.toFixed(0) + '%"></span>' +
        '<span class="bar-fill target" style="left:' + targetPct.toFixed(0) + '%"></span>' +
      '</div>' +
      '<span class="pct">' + curPct.toFixed(1) + '% → ' + targetPct + '%</span>' +
      '</div>';
  }
  el.innerHTML = html;
}

// ============================================================
// 历史
// ============================================================
function renderHistory() {
  const root = document.getElementById('history-content');
  // 清除上次的断月横幅
  document.querySelectorAll('.gap-banner').forEach(el => el.remove());
  if (state.historyView === 'matrix') { renderMatrixView(); return; }
  const allSorted = getSortedSnapshots().slice().reverse();
  if (allSorted.length === 0) {
    root.innerHTML = '<div class="empty"><div class="glyph">∅</div><p>历史是耐心的回声</p><div class="hint">请先录入第一份月度快照，数据会在这里呈现</div></div>';
    return;
  }

  // 搜索过滤
  const query = (document.getElementById('history-search').value || '').trim().toLowerCase();
  const sorted = query ? allSorted.filter(s => s.month.includes(query)) : allSorted;

  let html = '<div class="table-card"><div class="table-header"><h3>月度快照</h3><span class="meta">共 ' + sorted.length + ' 个月' + (query ? ' · 搜索: ' + escapeHtml(query) : '') + '</span></div><table class="data-table"><thead><tr><th>月份</th><th class="right">总资产</th><th class="right">市场盈亏</th><th class="right">净入金</th><th class="right">环比变动</th><th></th></tr></thead><tbody>';
  for (let i = 0; i < sorted.length; i++) {
    const s = sorted[i];
    const prevInAll = allSorted.find(x => x.month === ymPrev(s.month)) || null;
    const total = snapshotTotal(s);
    const pnl = monthlyPnL(s, prevInAll);
    const flow = snapshotFlow(s);
    const change = prevInAll ? total - snapshotTotal(prevInAll) : null;
    const pct = (change !== null && prevInAll) ? (change / snapshotTotal(prevInAll) * 100) : null;
    const trendArrow = pct !== null ? (pct > 0.5 ? '<span class="trend-arrow up">↗</span>' : (pct < -0.5 ? '<span class="trend-arrow dn">↘</span>' : '<span class="trend-arrow flat">→</span>')) : '';
    const pnlClass = pnl > 0 ? 'pos' : (pnl < 0 ? 'neg' : '');
    html += '<tr>' +
      '<td>' + trendArrow + '<span style="cursor:pointer;color:var(--accent)" title="查看明细" data-month-drill="' + s.month + '">' + s.month + '</span></td>' +
      '<td class="right">' + fmt(total) + '</td>' +
      '<td class="right ' + pnlClass + '">' + fmtSign(pnl) + '</td>' +
      '<td class="right">' + fmtSign(flow) + '</td>' +
      '<td class="right ' + (pct !== null ? (pct > 0 ? 'pos' : (pct < 0 ? 'neg' : '')) : '') + '">' + (pct !== null ? (pct > 0 ? '+' : '') + pct.toFixed(2) + '%' : '—') + '</td>' +
      '<td class="right">' +
        '<button class="icon-btn" data-edit-month="' + s.month + '">编辑</button> ' +
        '<button class="icon-btn danger" data-del-month="' + s.month + '">删除</button>' +
      '</td>' +
    '</tr>';
  }
  html += '</tbody></table></div>';
  root.innerHTML = html;

  // 空搜索结果
  if (sorted.length === 0) {
    root.innerHTML = '<div class="empty"><div class="glyph">∅</div><p>无匹配月份</p></div>';
  }

  // 断月检测（仅非搜索模式）
  if (!query && allSorted.length >= 2) {
    const all = getSortedSnapshots();
    const minM = all[0].month, maxM = all[all.length - 1].month;
    const gaps = [];
    let cur = minM;
    while (cur < maxM) {
      const nextM = ymNext(cur);
      if (!all.some(s => s.month === nextM)) gaps.push(nextM);
      cur = nextM;
    }
    if (gaps.length > 0) {
      const gapHtml = document.createElement('div');
      gapHtml.className = 'gap-banner';
      gapHtml.innerHTML = '📋 发现 <strong>' + gaps.length + '</strong> 个缺失月份：' +
        gaps.map(m => '<span class="gap-chip" data-gap="' + m + '">' + m + '</span>').join(' ');
      root.parentNode.insertBefore(gapHtml, root.nextSibling);
      gapHtml.querySelectorAll('.gap-chip').forEach(el => {
        el.addEventListener('click', () => {
          state.editingMonth = el.dataset.gap;
          navTo('entry');
        });
      });
    }
  }

  root.querySelectorAll('[data-edit-month]').forEach(b => b.addEventListener('click', () => {
    state.editingMonth = b.dataset.editMonth;
    navTo('entry');
  }));
  root.querySelectorAll('[data-del-month]').forEach(b => b.addEventListener('click', async () => {
    const m = b.dataset.delMonth;
    if (!confirm(`确认删除 ${m} 这一月的快照？`)) return;
    state.snapshots = state.snapshots.filter(s => s.month !== m);
    await persistVault();
    renderHistory();
    showToast('已删除');
  }));
  // 月份名称点击 → 打开盈亏明细抽屉
  root.querySelectorAll('[data-month-drill]').forEach(b => b.addEventListener('click', () => {
    openDrawer('pnl', b.dataset.monthDrill);
  }));
}

function runHistoryCompare() {
  const a = document.getElementById('history-compare-a').value;
  const b = document.getElementById('history-compare-b').value;
  const el = document.getElementById('history-compare-result');
  if (!a || !b || a === b) { el.style.display = 'none'; return; }

  const sorted = getSortedSnapshots();
  const snapA = sorted.find(s => s.month === a);
  const snapB = sorted.find(s => s.month === b);
  if (!snapA || !snapB) { el.style.display = 'none'; return; }

  const totalA = snapshotTotal(snapA);
  const totalB = snapshotTotal(snapB);
  const diff = totalB - totalA;
  const flowA = snapshotFlow(snapA);
  const flowB = snapshotFlow(snapB);
  // 期间市场盈亏（从 A 到 B 的累计）
  const startIdx = sorted.indexOf(snapA);
  const endIdx = sorted.indexOf(snapB);
  let cumPnL = 0;
  for (let i = Math.min(startIdx, endIdx) + 1; i <= Math.max(startIdx, endIdx); i++) {
    cumPnL += monthlyPnL(sorted[i], sorted[i - 1]);
  }
  const months = Math.abs(endIdx - startIdx);

  el.style.display = '';
  el.innerHTML = '<div style="font-size:13px;font-weight:600;margin-bottom:4px;color:var(--ink-2)">' + a + ' → ' + b + ' (' + months + '个月)</div>' +
    '<div class="compare-grid">' +
    '<div class="compare-card"><div class="label">起点总资产</div><div class="value">' + fmt(totalA) + '</div><div class="sub">' + a + '</div></div>' +
    '<div class="compare-card"><div class="label">终点总资产</div><div class="value">' + fmt(totalB) + '</div><div class="sub">' + b + '</div></div>' +
    '<div class="compare-card"><div class="label">总变化</div><div class="value ' + (diff > 0 ? 'pos' : (diff < 0 ? 'neg' : '')) + '">' + fmtSign(diff) + '</div><div class="sub">总资产增减</div></div>' +
    '<div class="compare-card"><div class="label">期间市场盈亏</div><div class="value ' + (cumPnL > 0 ? 'pos' : (cumPnL < 0 ? 'neg' : '')) + '">' + fmtSign(cumPnL) + '</div><div class="sub">已剔除入金</div></div>' +
    '</div>';
}

function exportCSV() {
  const sorted = getSortedSnapshots().slice().reverse();
  if (sorted.length === 0) { showToast('无数据可导出', 'error'); return; }
  const csvQ = s => '"' + String(s).replace(/"/g, '""') + '"';
  let csv = '﻿月份,总资产,市场盈亏,净入金,较上月变动\n';
  for (let i = 0; i < sorted.length; i++) {
    const s = sorted[i];
    const prev = sorted[i + 1] || null;
    const total = snapshotTotal(s);
    const pnl = monthlyPnL(s, prev);
    const flow = snapshotFlow(s);
    const change = prev ? total - snapshotTotal(prev) : 0;
    csv += s.month + ',' + total + ',' + pnl + ',' + flow + ',' + change + '\n';
  }
  // 账户明细行（最新月份各账户余额）
  const latest = sorted[0];
  csv += '\n\n最新月份账户明细\n';
  csv += '账户,分组,类型,余额\n';
  for (const a of state.accounts) {
    const e = latest.entries[a.id];
    if (e && e.balance) {
      csv += csvQ(a.name) + ',' + csvQ(a.group) + ',' + a.type + ',' + (Number(e.balance) || 0) + '\n';
    }
  }

  const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = '资产负债表-' + new Date().toISOString().slice(0, 10) + '.csv';
  link.click();
  URL.revokeObjectURL(url);
  showToast('已导出 CSV');
}

// ============================================================
// 历史页事件绑定
// ============================================================
document.getElementById('history-search').addEventListener('input', () => renderHistory());
document.getElementById('history-compare-a').addEventListener('change', runHistoryCompare);
document.getElementById('history-compare-b').addEventListener('change', runHistoryCompare);
document.getElementById('export-csv').addEventListener('click', exportCSV);

// 历史页视图切换（列表 / 对照表）
document.querySelectorAll('#history-view-toggle button').forEach(b => {
  b.addEventListener('click', () => {
    state.historyView = b.dataset.hview;
    document.querySelectorAll('#history-view-toggle button').forEach(x => x.classList.toggle('active', x === b));
    const isList = state.historyView === 'list';
    const searchEl = document.getElementById('history-search');
    const csvEl = document.getElementById('export-csv');
    const cmpA = document.getElementById('history-compare-a');
    const cmpB = document.getElementById('history-compare-b');
    if (searchEl) searchEl.style.display = isList ? '' : 'none';
    if (csvEl) csvEl.style.display = isList ? '' : 'none';
    if (cmpA) cmpA.style.display = isList ? '' : 'none';
    if (cmpB) cmpB.style.display = isList ? '' : 'none';
    if (cmpA) {
      const compareRow = cmpA.closest('div');
      if (compareRow) {
        const vsSpan = compareRow.querySelector('span');
        if (vsSpan) vsSpan.style.display = isList ? '' : 'none';
      }
    }
    renderHistory();
  });
});

function renderMatrixView() {
  const root = document.getElementById('history-content');
  const sorted = getSortedSnapshots();
  if (sorted.length === 0) {
    root.innerHTML = '<div class="empty"><div class="glyph">∅</div><p>暂无数据</p></div>';
    return;
  }
  const activeAccounts = state.accounts.filter(a => !a.archived);
  // 按分组聚类
  const grouped = {};
  for (const a of activeAccounts) {
    if (!grouped[a.group]) grouped[a.group] = [];
    grouped[a.group].push(a);
  }
  const groups = state.groupOrder.filter(g => grouped[g] && grouped[g].length > 0);
  // 展开列顺序：按分组聚类
  const colAccounts = [];
  for (const g of groups) {
    for (const a of grouped[g]) colAccounts.push(a);
  }

  // 构建表头：两层
  let html = '<div class="matrix-wrap"><table class="matrix-table"><thead>';
  html += '<tr><th>月份</th>';
  for (const g of groups) {
    const cnt = grouped[g].length;
    html += '<th class="group-header" colspan="' + cnt + '">' + escapeHtml(g) + '</th>';
  }
  html += '<th>总资产</th></tr>';
  html += '<tr><th></th>';
  for (const a of colAccounts) {
    html += '<th>' + escapeHtml(a.name) + '</th>';
  }
  html += '<th></th></tr></thead><tbody>';

  for (const s of sorted) {
    html += '<tr>';
    html += '<td>' + s.month + '</td>';
    for (const a of colAccounts) {
      const e = s.entries[a.id];
      const bal = e && e.balance !== null && e.balance !== undefined ? Number(e.balance) : null;
      const cls = bal !== null && bal < 0 ? 'neg-val' : '';
      html += '<td class="mono ' + cls + '">' + (bal !== null ? Math.abs(bal).toLocaleString('zh-CN') : '—') + '</td>';
    }
    html += '<td class="mono" style="font-weight:600">' + snapshotTotal(s).toLocaleString('zh-CN') + '</td>';
    html += '</tr>';
  }
  html += '</tbody></table></div>';
  root.innerHTML = html;
}

// ============================================================
// 导入 / 导出 / 重置 / 改密码
// ============================================================
document.getElementById('export-data').addEventListener('click', async () => {
  const meta = await dbGet('meta');
  const vault = await dbGet('vault');
  const data = {
    type: 'asset-ledger-encrypted-backup',
    version: 2,
    exportedAt: new Date().toISOString(),
    meta,
    vault,
  };
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = '资产账本-加密备份-' + new Date().toISOString().slice(0, 10) + '.json';
  a.click();
  URL.revokeObjectURL(url);
  localStorage.setItem('asset-ledger-last-backup', Date.now());
  updateBackupBadge();
  showToast('已导出加密备份');
});

document.getElementById('import-data').addEventListener('click', () => document.getElementById('import-file').click());
document.getElementById('import-file').addEventListener('change', async (e) => {
  const f = e.target.files[0];
  if (!f) return;
  try {
    const text = await f.text();
    const data = JSON.parse(text);
    if (data.type !== 'asset-ledger-encrypted-backup') throw new Error('文件格式不正确');

    if (!confirm('导入将覆盖当前所有数据，确认？\n\n提示：导入后需用备份的密码或 Passkey 解锁。')) return;

    if (data.version === 1) {
      // 旧版备份兼容
      const pwd = prompt('请输入此备份的主密码：');
      if (!pwd) return;
      const salt = b64ToBuf(data.salt);
      const wKey = await deriveKeyFromPassword(pwd, salt);
      // v1 没有 wrapping，直接是 verifier+payload；不再支持也来不及，做简单兼容
      throw new Error('旧版备份不再支持，请用最近的备份');
    }
    if (data.meta && data.vault) {
      await dbPut('meta', data.meta);
      await dbPut('vault', data.vault);
      showToast('已导入，正在重新解锁');
      lockNow();
    } else {
      throw new Error('备份文件不完整');
    }
  } catch (err) {
    showToast('导入失败：' + err.message, 'error');
  }
  e.target.value = '';
});

document.getElementById('reset-data').addEventListener('click', async () => {
  if (!confirm('清空所有数据并恢复默认账户？此操作无法撤销。建议先导出加密备份。')) return;
  if (!confirm('再次确认：所有快照、账户、密码、Passkey 都将被清除。')) return;
  await dbClearAll();
  lockNow();
  showToast('已重置');
});

// 本地无感冷备份
document.getElementById('enable-local-backup').addEventListener('click', async () => {
  try {
    localBackupDirectoryHandle = await window.showDirectoryPicker({ mode: 'readwrite' });
    document.getElementById('backup-status').style.display = '';
    showToast('本地备份目录挂载成功');
  } catch (e) {
    if (e.name !== 'AbortError') {
      showToast('授权失败或浏览器不支持此功能', 'error');
    }
  }
});

// 修改密码
document.getElementById('change-password').addEventListener('click', async () => {
  const meta = await dbGet('meta');
  if (!meta || !meta.wrappedKeyByPassword) {
    if (confirm('当前账本未配置密码（仅 Passkey）。是否要添加一个备用密码？')) {
      const np = prompt('设置新的备用密码（至少 6 位）：');
      if (!np) return;
      if (np.length < 6) { showToast('密码至少 6 位', 'error'); return; }
      const np2 = prompt('再次输入确认：');
      if (np !== np2) { showToast('两次输入不一致', 'error'); return; }
      const newSalt = randomBytes(CRYPTO_CONFIG.saltLen);
      const wKey = await deriveKeyFromPassword(np, newSalt);
      const wrappedKeyByPassword = await wrapMasterKey(state.masterKey, wKey);
      meta.salt = bufToB64(newSalt);
      meta.wrappedKeyByPassword = wrappedKeyByPassword;
      await dbPut('meta', meta);
      state.cachedMeta = meta;
      showToast('已添加备用密码');
    }
    return;
  }
  document.getElementById('pwd-current').value = '';
  document.getElementById('pwd-new').value = '';
  document.getElementById('pwd-new-confirm').value = '';
  document.getElementById('password-modal').classList.add('active');
  setTimeout(() => document.getElementById('pwd-current').focus(), 50);
});
document.getElementById('pwd-cancel').addEventListener('click', () => {
  document.getElementById('password-modal').classList.remove('active');
});
document.getElementById('pwd-save').addEventListener('click', async () => {
  const cur = document.getElementById('pwd-current').value;
  const nw = document.getElementById('pwd-new').value;
  const nwc = document.getElementById('pwd-new-confirm').value;
  if (!cur || !nw) { showToast('请填写完整', 'error'); return; }
  if (nw.length < 6) { showToast('新密码至少 6 位', 'error'); return; }
  if (nw !== nwc) { showToast('两次新密码不一致', 'error'); return; }

  const meta = await dbGet('meta');
  try {
    const oldSalt = b64ToBuf(meta.salt);
    const oldWKey = await deriveKeyFromPassword(cur, oldSalt);
    await unwrapMasterKey(meta.wrappedKeyByPassword, oldWKey);
  } catch {
    showToast('当前密码不正确', 'error'); return;
  }

  const newSalt = randomBytes(CRYPTO_CONFIG.saltLen);
  const newWKey = await deriveKeyFromPassword(nw, newSalt);
  const wrappedKeyByPassword = await wrapMasterKey(state.masterKey, newWKey);

  meta.salt = bufToB64(newSalt);
  meta.wrappedKeyByPassword = wrappedKeyByPassword;
  await dbPut('meta', meta);
  state.cachedMeta = meta;

  document.getElementById('password-modal').classList.remove('active');
  showToast('密码已修改');
});

// ============================================================
// Passkey 管理
// ============================================================
document.getElementById('manage-passkey').addEventListener('click', async () => {
  const meta = await dbGet('meta');
  const status = document.getElementById('passkey-status');
  const addBtn = document.getElementById('passkey-add');
  const removeBtn = document.getElementById('passkey-remove');

  if (!isPRFSupported()) {
    status.innerHTML = '⚠️ 此浏览器不支持 Passkey PRF 扩展。<br>仅 Safari 18+ 与 Chrome 132+ 等较新浏览器可用。';
    addBtn.style.display = 'none';
    removeBtn.style.display = 'none';
  } else if (meta && meta.passkeyCredId) {
    status.innerHTML = '✅ 已注册 Passkey。可用 Touch ID / Face ID 解锁。<br><br><span style="color:var(--ink-3);font-size:13px">删除后将无法用 Passkey 解锁，确保你还记得密码。</span>';
    addBtn.style.display = 'none';
    removeBtn.style.display = '';
  } else if (meta && meta.wrappedKeyByPassword) {
    status.innerHTML = '当前用密码加密。可添加 Passkey 作为快捷解锁方式（密码仍然有效，两者并存）。';
    addBtn.style.display = '';
    removeBtn.style.display = 'none';
  } else {
    status.innerHTML = '账本未初始化';
    addBtn.style.display = 'none';
    removeBtn.style.display = 'none';
  }

  document.getElementById('passkey-modal').classList.add('active');
});
document.getElementById('passkey-modal-cancel').addEventListener('click', () => {
  document.getElementById('passkey-modal').classList.remove('active');
});

// 添加 Passkey（在已用密码的情况下）
document.getElementById('passkey-add').addEventListener('click', async () => {
  try {
    const { credentialId, prfOutput } = await registerPasskey();
    const wKey = await deriveKeyFromPRF(prfOutput);
    const wrappedKeyByPasskey = await wrapMasterKey(state.masterKey, wKey);

    const meta = await dbGet('meta');
    meta.passkeyCredId = credentialId;
    meta.wrappedKeyByPasskey = wrappedKeyByPasskey;
    await dbPut('meta', meta);
    state.cachedMeta = meta;

    document.getElementById('passkey-modal').classList.remove('active');
    showToast('Passkey 已添加');
  } catch (err) {
    showToast('注册失败：' + (err.message || '未知错误'), 'error');
  }
});

// 移除 Passkey
document.getElementById('passkey-remove').addEventListener('click', async () => {
  const meta = await dbGet('meta');
  if (!meta.wrappedKeyByPassword) {
    if (!confirm('警告：当前账本仅靠 Passkey 加密。删除前必须先设置一个备用密码，否则数据将无法解锁。\n\n点击确定后将提示设置密码。')) return;
    const np = prompt('设置一个备用密码（至少 6 位）：');
    if (!np) return;
    if (np.length < 6) { showToast('密码至少 6 位', 'error'); return; }
    const np2 = prompt('再次输入确认：');
    if (np !== np2) { showToast('两次输入不一致', 'error'); return; }
    const newSalt = randomBytes(CRYPTO_CONFIG.saltLen);
    const wKey = await deriveKeyFromPassword(np, newSalt);
    const wrappedKeyByPassword = await wrapMasterKey(state.masterKey, wKey);
    meta.salt = bufToB64(newSalt);
    meta.wrappedKeyByPassword = wrappedKeyByPassword;
    await dbPut('meta', meta);
    state.cachedMeta = meta;
    showToast('已设置备用密码');
  }
  if (!confirm('确认删除 Passkey？仅会移除此应用的 Passkey 关联，不会影响系统钥匙串。')) return;
  delete meta.passkeyCredId;
  delete meta.wrappedKeyByPasskey;
  await dbPut('meta', meta);
  state.cachedMeta = meta;
  document.getElementById('passkey-modal').classList.remove('active');
  showToast('Passkey 已移除');
});

// ============================================================
// 启动
// ============================================================

// 全局错误捕获：任何 persistVault 失败都不会被静默吞掉
window.addEventListener('unhandledrejection', (e) => {
  const msg = (e.reason && (e.reason.message || e.reason.toString())) || '';
  // 只对"写入校验"失败强提示，避免被无关错误干扰
  if (msg.indexOf('写入') >= 0 || msg.indexOf('校验') >= 0 || msg.indexOf('persistVault') >= 0) {
    console.error('云端写入失败:', e.reason);
    showToast('⚠️ 云端写入失败。请检查网络后重试，并导出加密备份。', 'error');
  }
});

// ============ 跃然纸上 · 滚动浮现 ============
function initScrollReveal() {
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('revealed');
        observer.unobserve(entry.target);
      }
    });
  }, { threshold: 0.08, rootMargin: '0px 0px -20px 0px' });
  document.querySelectorAll('.reveal').forEach(el => observer.observe(el));
}


(async function init() {
  const savedTheme = localStorage.getItem('asset-theme') || 'system';
  applyTheme(savedTheme);
  await unlockOrInit();
  // 首次加载后激活滚动浮现
  requestAnimationFrame(() => { requestAnimationFrame(initScrollReveal); });
})();
