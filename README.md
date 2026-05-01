# Asset Ledger（个人资产负债表）

> 端到端加密的个人资产负债表 — 跨券商、跨银行、跨币种的净值全景。**数据由你掌控，服务器只能看到密文。**

[![vanilla JS](https://img.shields.io/badge/vanilla-JS-blue)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![AES-256-GCM](https://img.shields.io/badge/E2E-AES--256--GCM-green)](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
[![deploy](https://img.shields.io/badge/deploy-Cloudflare%20Workers-orange)](https://workers.cloudflare.com/)
[![license](https://img.shields.io/badge/license-MIT-brightgreen)](./LICENSE)

---

| 🔐 安全模型 | 📊 Dashboard | 📝 录入 | 📅 历史 |
|:--:|:--:|:--:|:--:|
| 主密码 / Passkey 双解锁 | Hero 资产总览 + 水位线透视 | 月度快照批量录入 | 列表 + 矩阵双视图 |
| PBKDF2 250K → AES-GCM | Percento 总资产折线图 | 自动上月复制 + Delta 环比 | TWR / XIRR 收益率 |
| 全程密文 · 服务端零明文 | 盈亏柱图 + 环形图钻取 | 账户 CRUD + 分组管理 | CSV 导出 + 断月检测 |
| 本地镜像 + 冷备份 | 滚动浮现 · 紧凑 Hero 吸附 | 冲突检测 + 回读校验 | 一键云端刷新 |

---

## 架构

```
index.html (单文件 SPA · ~7400 行 · 零框架)
        │
        ▼
┌──────────────────────────────────────┐
│         Web Crypto API               │
│  AES-256-GCM  encrypt / decrypt      │
│  PBKDF2 250K   deriveKey             │
│  WebAuthn PRF  passkey unlock        │
└──────────────┬───────────────────────┘
               │  { iv, cipher }
               ▼
┌──────────────────────────────────────┐
│     Cloudflare Worker API            │
│  /api/vault  ·  /api/meta  ·  /api/bg│
│  D1 (SQLite) · 键值存储 · 冲突检测    │
└──────────────────────────────────────┘
```

| 层 | 技术 |
|:--|:--|
| 前端 | Vanilla JS · 单文件 SPA · 零构建 |
| 加密 | Web Crypto API · AES-256-GCM · PBKDF2 250K · WebAuthn PRF |
| 图表 | Chart.js 4.x · Percento 折线 · Doughnut · Bar + 十字准星插件 |
| 运算 | Big.js · 任意精度十进制 |
| 后端 | Cloudflare Workers · 5 文件 · ~200 行 |
| 数据库 | Cloudflare D1 (SQLite) · 键值模式 |
| 主题 | Apple 浅色 · 素白瓷白 · Linear 深色 · CSS 变量驱动 |
| 部署 | GitHub Actions → `wrangler deploy` · push 即上线 |

## 部署

**3 步上线：**

| # | 操作 | 说明 |
|:--|:--|:--|
| 1 | 创建 D1 数据库 | Cloudflare Dashboard → D1 → 执行 [建表 SQL](#建表-sql) |
| 2 | 设置 3 个 Secrets | `CLOUDFLARE_API_TOKEN` · `CLOUDFLARE_ACCOUNT_ID` · `D1_DATABASE_ID` |
| 3 | `git push main` | GitHub Actions 自动部署 |

```bash
# 本地调试
cp wrangler.example.toml wrangler.toml  # 填入 D1 database_id
npx wrangler dev
```

### 建表 SQL

```sql
CREATE TABLE IF NOT EXISTS vault (
  id TEXT PRIMARY KEY,
  payload TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS meta (
  id TEXT PRIMARY KEY,
  salt TEXT NOT NULL,
  verifier TEXT NOT NULL
);
```

## 边界

- D1 免费额度：5GB 存储 + 500 万次读/天 + 10 万次写/天
- 单用户设计 · Passkey PRF 需 Safari 18+ / Chrome 132+
- 本地冷备份需 Chromium · Web Crypto 需 HTTPS 或 localhost
