// ============================================================
// 金融计算核心 — 纯函数，无 DOM / 无 state 依赖
//
// 作为经典脚本在浏览器中加载（函数声明进入全局作用域，供 app.js 调用）；
// 同一份源码由 test/finance.test.mjs 在 node:vm 沙箱中加载做单元测试。
// 唯一外部依赖：Big（big.js 全局，浏览器由 vendor 脚本提供，测试中注入）。
// ============================================================

function toBig(val) {
  return new Big(val || 0);
}
function snapshotTotal(snap) {
  if (!snap) return 0;
  return Object.values(snap.entries || {}).reduce((s, e) => s.plus(toBig(e.balance)), Big(0)).toNumber();
}
function snapshotFlow(snap) {
  if (!snap) return 0;
  return Object.values(snap.entries || {}).reduce((s, e) => s.plus(toBig(e.flow)), Big(0)).toNumber();
}
function monthlyPnL(curr, prev) {
  if (!curr || !prev) return 0; // 基准月：无前月可对比，盈亏不可知
  const currTotal = Big(snapshotTotal(curr));
  const prevTotal = Big(snapshotTotal(prev));
  const flow = Big(snapshotFlow(curr));
  return currTotal.minus(prevTotal).minus(flow).toNumber();
}

// ============================================================
// XIRR 核心引擎（牛顿迭代法）
// ============================================================
function calculateXIRR(cashFlows, guess = 0.1) {
  if (cashFlows.length < 2) return null;
  // 必须同时存在投入（负）和结余/转出（正）
  let hasPos = false, hasNeg = false;
  for (const cf of cashFlows) {
    if (cf.amount > 0.01) hasPos = true;
    if (cf.amount < -0.01) hasNeg = true;
  }
  if (!hasPos || !hasNeg) return null;
  const maxIter = 100;
  const tol = 1e-6;
  let r = guess;
  for (let i = 0; i < maxIter; i++) {
    let f = 0, df = 0;
    for (let j = 0; j < cashFlows.length; j++) {
      const { amount, days } = cashFlows[j];
      const term = Math.pow(1 + r, days / 365.0);
      if (isNaN(term) || !isFinite(term)) return null;
      f += amount / term;
      df -= (days / 365.0) * amount / (term * (1 + r));
    }
    if (Math.abs(df) < 1e-10 || isNaN(df) || isNaN(f)) return null;
    const nextR = r - f / df;
    if (Math.abs(nextR - r) < tol) return nextR;
    r = nextR;
  }
  return null;
}
function daysBetween(monthA, monthB) {
  return (new Date(monthB + '-01') - new Date(monthA + '-01')) / 86400000;
}
