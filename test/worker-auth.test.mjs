// Worker 写保护（TOFU 令牌）单元测试 — 用真实 worker 模块 + 内存 D1
// 运行：node --test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import worker from '../worker/index.js';

function makeEnv() {
  const tables = { vault: new Map(), meta: new Map() };
  const DB = {
    prepare(sql) {
      return {
        _args: [],
        bind(...a) { this._args = a; return this; },
        async first() {
          const m = sql.match(/FROM (\w+) WHERE id = (?:\?|'(\w+)')/);
          return tables[m[1]].get(m[2] || this._args[0]) || null;
        },
        async run() {
          if (/^INSERT INTO vault/.test(sql)) {
            const [id, payload, updated_at] = this._args;
            tables.vault.set(id, { id, payload, updated_at });
          } else if (/VALUES \('_auth'/.test(sql)) {
            tables.meta.set('_auth', { id: '_auth', salt: this._args[0], verifier: '{}' });
          } else if (/^INSERT INTO meta/.test(sql)) {
            const [id, salt, verifier] = this._args;
            tables.meta.set(id, { id, salt, verifier });
          } else if (/DELETE FROM meta WHERE id = '_auth'/.test(sql)) {
            tables.meta.delete('_auth');
          } else if (/DELETE FROM (\w+) WHERE id = \?/.test(sql)) {
            tables[sql.match(/FROM (\w+)/)[1]].delete(this._args[0]);
          } else throw new Error('unhandled SQL: ' + sql);
        },
      };
    },
  };
  return { DB, _tables: tables };
}

const req = (method, path, { token, body } = {}) => {
  const headers = {};
  if (token) headers['Authorization'] = 'Bearer ' + token;
  if (body) headers['Content-Type'] = 'application/json';
  return new Request('http://localhost' + path, {
    method, headers, body: body ? JSON.stringify(body) : undefined,
  });
};
const call = (env, ...a) => worker.fetch(req(...a), env, {});

test('读取始终公开（密文由 AES-GCM 自保护）', async () => {
  const env = makeEnv();
  assert.equal((await call(env, 'GET', '/api/vault')).status, 200);
});

test('TOFU：携带令牌的首次 POST 完成绑定', async () => {
  const env = makeEnv();
  const r = await call(env, 'POST', '/api/vault', { token: 't1', body: { payload: { iv: 'a', cipher: 'b' } } });
  assert.equal(r.status, 200);
  assert.ok(env._tables.meta.get('_auth'));
});

test('绑定后：无令牌写入被拒（401）', async () => {
  const env = makeEnv();
  await call(env, 'POST', '/api/vault', { token: 't1', body: { payload: { iv: 'a', cipher: 'b' } } });
  assert.equal((await call(env, 'POST', '/api/vault', { body: { payload: { iv: 'x', cipher: 'y' } } })).status, 401);
});

test('绑定后：错误令牌写入被拒（401）', async () => {
  const env = makeEnv();
  await call(env, 'POST', '/api/vault', { token: 't1', body: { payload: { iv: 'a', cipher: 'b' } } });
  assert.equal((await call(env, 'DELETE', '/api/vault', { token: 'wrong' })).status, 401);
});

test('绑定后：正确令牌写入通过（200）', async () => {
  const env = makeEnv();
  await call(env, 'POST', '/api/vault', { token: 't1', body: { payload: { iv: 'a', cipher: 'b' } } });
  assert.equal((await call(env, 'POST', '/api/vault', { token: 't1', body: { payload: { iv: 'c', cipher: 'd' } } })).status, 200);
});

test('DELETE 不建立 TOFU 绑定（重置流程不会回写令牌）', async () => {
  const env = makeEnv();
  // 未绑定状态下携带令牌 DELETE，不应绑定
  await call(env, 'DELETE', '/api/vault', { token: 'whatever' });
  assert.equal(env._tables.meta.get('_auth'), undefined);
});

test('重置：DELETE /api/meta 清除数据与令牌绑定', async () => {
  const env = makeEnv();
  await call(env, 'POST', '/api/meta', { token: 't1', body: { salt: 's', verifier: {} } });
  assert.ok(env._tables.meta.get('_auth'));
  await call(env, 'DELETE', '/api/meta', { token: 't1' });
  assert.equal(env._tables.meta.get('_auth'), undefined);
  assert.equal(env._tables.meta.get('main'), undefined);
});

test('TOFU 窗口：未绑定时匿名写入放行但不绑定，合法用户仍可接管', async () => {
  const env = makeEnv();
  // 攻击者抢先无令牌写入
  assert.equal((await call(env, 'POST', '/api/meta', { body: { salt: 's', verifier: {} } })).status, 200);
  assert.equal(env._tables.meta.get('_auth'), undefined); // 未绑定
  // 合法用户携带令牌接管
  await call(env, 'POST', '/api/vault', { token: 'legit', body: { payload: { iv: 'a', cipher: 'b' } } });
  assert.ok(env._tables.meta.get('_auth'));
  // 此后攻击者被拒
  assert.equal((await call(env, 'POST', '/api/vault', { body: { payload: { iv: 'x', cipher: 'y' } } })).status, 401);
});
