// 金融计算核心单元测试 — 在 node:vm 沙箱中加载真实的 js/finance.js 源码
// （配合 vendored big.js），对照独立基准验证 XIRR / 盈亏 / 快照汇总。
// 运行：npm test
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import vm from 'node:vm';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const ctx = { Math, Date, Object, isNaN, isFinite };
vm.createContext(ctx);
vm.runInContext(readFileSync(join(root, 'js/vendor/big.min.js'), 'utf8'), ctx);
vm.runInContext(readFileSync(join(root, 'js/finance.js'), 'utf8'), ctx);
const { toBig, snapshotTotal, snapshotFlow, monthlyPnL, calculateXIRR, daysBetween } = ctx;

const near = (a, b, eps = 1e-4) => Math.abs(a - b) <= eps;
const snap = (entries) => ({ entries });

// ---------- 快照汇总 ----------
test('snapshotTotal: 多账户求和（含负债负值）', () => {
  const s = snap({ a: { balance: 10000 }, b: { balance: 5000 }, c: { balance: -2000 } });
  assert.equal(snapshotTotal(s), 13000);
});

test('snapshotTotal: 浮点精度由 Big 保证（0.1+0.2=0.3）', () => {
  const s = snap({ a: { balance: 0.1 }, b: { balance: 0.2 } });
  assert.equal(snapshotTotal(s), 0.3);
});

test('snapshotTotal: 空 / null 快照返回 0', () => {
  assert.equal(snapshotTotal(snap({})), 0);
  assert.equal(snapshotTotal(null), 0);
});

test('snapshotFlow: 净流入求和（出金为负）', () => {
  const s = snap({ a: { balance: 1, flow: 3000 }, b: { balance: 1, flow: -500 } });
  assert.equal(snapshotFlow(s), 2500);
});

// ---------- 月度盈亏 ----------
test('monthlyPnL: 盈亏 = 期末 - 期初 - 净流入', () => {
  // 期初 100000，本月净入 5000，期末 108000 → 市场盈亏 3000
  const prev = snap({ a: { balance: 100000, flow: 0 } });
  const curr = snap({ a: { balance: 108000, flow: 5000 } });
  assert.equal(monthlyPnL(curr, prev), 3000);
});

test('monthlyPnL: 纯入金无增长 → 盈亏 0（不把入金算成盈利）', () => {
  const prev = snap({ a: { balance: 50000, flow: 0 } });
  const curr = snap({ a: { balance: 60000, flow: 10000 } });
  assert.equal(monthlyPnL(curr, prev), 0);
});

test('monthlyPnL: 基准月（无前月）返回 0', () => {
  assert.equal(monthlyPnL(snap({ a: { balance: 1 } }), null), 0);
});

test('monthlyPnL: 出金情况下的盈亏（期末+出金对比期初）', () => {
  // 期初 100000，出金 -20000，期末 82000 → 盈亏 = 82000-100000-(-20000)=2000
  const prev = snap({ a: { balance: 100000, flow: 0 } });
  const curr = snap({ a: { balance: 82000, flow: -20000 } });
  assert.equal(monthlyPnL(curr, prev), 2000);
});

// ---------- daysBetween ----------
test('daysBetween: 整月跨度', () => {
  assert.equal(daysBetween('2026-01', '2026-02'), 31);
  assert.equal(daysBetween('2026-01', '2026-03'), 59); // 2026 平年：31+28
  assert.equal(daysBetween('2026-01', '2027-01'), 365);
});

test('daysBetween: 闰年 2 月', () => {
  assert.equal(daysBetween('2024-02', '2024-03'), 29);
});

// ---------- XIRR（对照 /tmp 独立 bisection 基准）----------
test('XIRR: 单笔投入一年 +10% 收益', () => {
  const r = calculateXIRR([{ amount: -10000, days: 0 }, { amount: 11000, days: 365 }]);
  assert.ok(near(r, 0.10), `期望 ≈0.10，得到 ${r}`);
});

test('XIRR: 分批投入（中途加仓）', () => {
  const r = calculateXIRR([
    { amount: -10000, days: 0 }, { amount: -5000, days: 180 }, { amount: 16500, days: 365 },
  ]);
  assert.ok(near(r, 0.120354), `期望 ≈0.120354，得到 ${r}`);
});

test('XIRR: 亏损场景 -10%', () => {
  const r = calculateXIRR([{ amount: -10000, days: 0 }, { amount: 9000, days: 365 }]);
  assert.ok(near(r, -0.10), `期望 ≈-0.10，得到 ${r}`);
});

test('XIRR: 半年 +20% → 年化约 44.14%', () => {
  const r = calculateXIRR([{ amount: -10000, days: 0 }, { amount: 12000, days: 182 }]);
  assert.ok(near(r, 0.441443, 1e-3), `期望 ≈0.4414，得到 ${r}`);
});

test('XIRR: 现金流不足 / 同号 → null（无解不强算）', () => {
  assert.equal(calculateXIRR([{ amount: -10000, days: 0 }]), null);          // 仅一笔
  assert.equal(calculateXIRR([{ amount: 10000, days: 0 }, { amount: 5000, days: 365 }]), null); // 全正
  assert.equal(calculateXIRR([{ amount: -10000, days: 0 }, { amount: -5000, days: 365 }]), null); // 全负
});

test('XIRR: 收益率为 0（平本）→ 约 0', () => {
  const r = calculateXIRR([{ amount: -10000, days: 0 }, { amount: 10000, days: 365 }]);
  assert.ok(near(r, 0, 1e-3), `期望 ≈0，得到 ${r}`);
});
