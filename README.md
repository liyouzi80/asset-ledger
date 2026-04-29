# Asset Ledger · 个人资产负债表

端到端加密的个人净值追踪系统。跨券商、跨银行、跨币种 — 数据由你掌控，服务器只能看到密文。

[![Tech](https://img.shields.io/badge/vanilla-JS-blue)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![Encryption](https://img.shields.io/badge/encryption-AES--256--GCM-green)](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
[![Deploy](https://img.shields.io/badge/deploy-Cloudflare%20Workers-orange)](https://workers.cloudflare.com/)
[![License](https://img.shields.io/badge/license-MIT-brightgreen)](./LICENSE)

---

## 产品总览

```
┌─────────────────────────────────────────────────────────────────────┐
│                         ASSET LEDGER                                │
│                    个人资产负债表 · E2E 加密                          │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│   🔐 安全模型                    📊 Dashboard                       │
│   ┌───────────────────┐         ┌─────────────────────────┐        │
│   │  主密码 / Passkey  │         │  Hero 资产总览            │        │
│   │      ↓             │         │  水位线透视 (流动/投资/   │        │
│   │  PBKDF2 250K 迭代  │         │     长期/负债率)         │        │
│   │      ↓             │         │  总资产折线图 (Percento)  │        │
│   │  AES-GCM 主密钥    │         │  盈亏堆叠柱图 + 钻取      │        │
│   │      ↓             │         │  资产分布环形图 + 下钻    │        │
│   │  密文落盘 (D1)     │         │  收益率走势 (TWR/XIRR)   │        │
│   └───────────────────┘         └─────────────────────────┘        │
│                                                                     │
│   📝 录入                        📅 历史分析                        │
│   ┌───────────────────┐         ┌─────────────────────────┐        │
│   │  月度快照批量录入   │         │  列表视图: 月总/PnL/净流  │        │
│   │  账户 CRUD + 分组   │         │  矩阵视图: 账户×月份透视  │        │
│   │  自动上月复制       │         │  收益率: TWR/简单/XIRR   │        │
│   │  Delta 环比计算     │         │  CSV导出 / 断月检测      │        │
│   │  异常变动提醒       │         │  同期对比工具             │        │
│   └───────────────────┘         └─────────────────────────┘        │
│                                                                     │
│   🎨 设计                                                           │
│   ┌─────────────────────────────────────────────────────────┐      │
│   │  Apple 浅色主题 (留白 + SF 克制蓝)                         │      │
│   │  Linear 深色主题 (极暗画布 + 半透白边框 + 蓝紫强调)         │      │
│   │  transitions.dev 动效 · 数字弹入 · 文本交换 · 面板浮现      │      │
│   │  响应式 374px+ · 紧凑 Hero 滚动吸附 · 滚动浮现动画          │      │
│   └─────────────────────────────────────────────────────────┘      │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

## 功能详解

### 📊 Dashboard · 净值总览

- **Hero 资产总览**：总资产 / 投资资产双视图切换（投资视图自动排除债权和"其他资产"组），水位线四段透视资产分布（流动 / 投资 / 长期 / 负债率），点击 Hero 打开资产明细抽屉
- **总资产折线图**：Percento 风格，hover 十字准星 + 实时 scrubbing 联动 Hero 数值更新
- **收益率走势**：累计收益率折线图，TWR / 简单加权 / XIRR / 盈亏额 四种指标，1M / 3M / 6M / YTD / 自定义 期间切换
- **每月盈亏柱图**：正负堆叠柱状图（绿涨红跌），市场回报 vs 净现金流分层，点击钻取月度明细
- **资产环形图**：按分组聚类 doughnut 图，点击分组钻取账户级余额
- **紧凑 Hero**：滚动时吸附顶部的悬浮导航条，含视图切换 + 迷你总资产

### 📝 录入 · 数据管理

- 月度快照批量录入，按分组排列账户行，支持 Dollar-value 格式化
- 账户 CRUD（新增 / 编辑 / 删除 / 归档），资金属性标签（投资 / 现金 / 债权 / 负债 / 长期）
- 分组管理（新增 / 重命名 / 删除），账户内拖拽排序
- 自动从上一月复制、Delta 环比计算、异常变动提醒（±20% 阈值可配置）
- 保存前冲突检测 + 云端回读校验（最多 3 次重试）+ 本地镜像同步落盘
- 草稿自动保存，浏览器意外刷新不丢失

### 📅 历史 · 回溯分析

- **列表视图**：搜索过滤，月度总资产 / 盈亏 / 净流，正负色标，编辑 / 删除操作
- **对照表视图**（Matrix）：账户 × 月份交叉透视，一屏尽览所有资产变动轨迹
- **收益率模块**：TWR（时间加权）/ 简单加权 / XIRR（Newton 迭代）/ 盈亏额 四种计算口径
- CSV 导出、断月检测（自动发现跳过的月份）、同期对比工具
- 一键从云端刷新数据

### 🔐 安全 · E2E 加密

```
主密码                      Passkey
  │                           │
  ▼                           ▼
PBKDF2                   WebAuthn PRF
250K 迭代 SHA-256           + HKDF
  │                           │
  ▼                           ▼
┌─────────────────────────────────┐
│       AES-GCM-256 主密钥         │  ← 缓存于 localStorage，刷新免重登
└──────────────┬──────────────────┘
               │
               ▼
┌─────────────────────────────────┐
│   加密账本 { iv, cipher }        │  ← 服务端全程不可见明文
└──────────────┬──────────────────┘
               │
               ▼
      Cloudflare D1 / 本地镜像
```

- AES-GCM-256 端到端加密，Web Crypto API 原生实现
- 双解锁路径：主密码（PBKDF2 250K 迭代）或 Passkey（WebAuthn PRF + HKDF）
- 首次设置强制密码模式，系统内按需注册 Passkey
- 主密钥缓存 localStorage，刷新免重登；锁定即销毁
- 云端数据全密文存储 — D1 只有 `{ iv, cipher }`，无法解密

### 💾 备份 · 数据安全

- 加密备份导出 / 导入（JSON 文件）
- 本地冷备份（File System Access API，Chromium 系浏览器，静默落盘）
- localStorage 本地镜像 — 每次云端写入同步一份加密副本到本地，防云端误删
- 恢复检测：云端为空时自动提示从本地镜像恢复

## 技术架构

```
index.html                    ← 单文件 SPA（~7400 行，零构建 / 零框架）
worker/
├── index.js                  ← Worker 路由分发（/api/meta, /api/vault, /api/bg）
├── meta.js                   ← 密钥元信息 CRUD（D1 meta 表）
├── vault.js                  ← 加密账本 CRUD + 冲突检测（D1 vault 表）
├── bg.js                     ← Bing 每日壁纸代理
└── shared.js                 ← CORS / 缓存头 / Body 大小校验
```

| 层级 | 技术 | 说明 |
|------|------|------|
| **前端** | Vanilla JS SPA · ~7400 行单文件 | 无 React/Vue，纯 DOM 操作 |
| **加密** | Web Crypto API · AES-256-GCM | PBKDF2 (250K) · WebAuthn PRF · HKDF |
| **图表** | Chart.js 4.x (CDN) | Percento 风格折线 · Doughnut · Bar + 自定义十字准星插件 |
| **运算** | Big.js (CDN) | 任意精度十进制，金融级计算 |
| **字体** | Inter + JetBrains Mono | Google Fonts CDN，系统字体栈兜底 |
| **后端** | Cloudflare Workers | ES Modules，~200 行，5 文件 |
| **数据库** | Cloudflare D1 (SQLite) | 键值模式，单行表 |
| **部署** | GitHub Actions + Wrangler v4 | push main 自动部署 |
| **主题** | CSS 变量驱动 · 双主题 | Apple 浅色 + Linear 深色，system-follow |
| **动效** | transitions.dev | 数字弹入 · 文本交换 · 面板浮现 · 图标变换 |

## 文件结构

```
asset-ledger/
├── index.html                  ← 完整前端应用（HTML + CSS + JS）
├── worker/                     ← Cloudflare Worker API
│   ├── index.js
│   ├── meta.js
│   ├── vault.js
│   ├── bg.js
│   └── shared.js
├── wrangler.example.toml       ← 部署配置模板
├── product-showcase.html       ← 产品展示大图（浏览器打开截图即可）
├── .github/workflows/deploy.yml ← GitHub Actions 自动部署
├── .gitignore
└── README.md
```

## 快速开始 · 部署

### 1. 创建 D1 数据库

Cloudflare Dashboard → **Workers & Pages** → **D1** → **Create**

数据库名填 `asset-ledger-db`，进入 Console 执行：

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

### 2. GitHub Actions 自动部署（推荐）

Fork 本仓库。Settings → Secrets and variables → Actions：

| Secret | 说明 |
|--------|------|
| `CLOUDFLARE_API_TOKEN` | API Token（My Profile → API Tokens） |
| `CLOUDFLARE_ACCOUNT_ID` | Account ID（Workers 右侧栏） |
| `D1_DATABASE_ID` | D1 数据库 ID |

推送 `main` 自动部署。

### 3. 手动部署

```bash
cp wrangler.example.toml wrangler.toml
# 编辑 wrangler.toml 填入 D1 database_id
npx wrangler deploy
```

部署后在 Worker → Settings → Triggers → Custom Domains 绑定域名。

### 4. 本地调试

```bash
npx wrangler dev
```

## 已知边界

- D1 免费额度：5GB 存储 + 500 万次读/天 + 10 万次写/天
- 单用户设计（无多租户 / 团队协作）
- Passkey PRF 需 Safari 18+ / Chrome 132+
- 本地冷备份需 Chromium（Chrome / Edge / Arc）
- Web Crypto API 要求 HTTPS 或 localhost 环境
