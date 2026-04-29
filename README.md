# Asset Ledger · 个人资产负债表

端到端加密的资产追踪系统。单文件 HTML SPA + Cloudflare Worker + D1，双主题（Apple 浅色 / Linear 深色），Chart.js 4.x + Big.js，GitHub Actions 自动部署。

## 功能概览

### 首页 Dashboard
- **Hero 资产总览**：总资产/投资资产双视图切换，水位线透视资产分布（流动/投资/长期/负债率），点击 Hero 打开资产明细抽屉
- **总资产曲线**：Percento 风格折线图，hover 十字准星 + 实时 scrubbing 联动 Hero 数值，Y 轴 ¥万标签
- **收益率走势**：正负双色面积图（绿盈/红亏），TWR / 简单加权 / XIRR / 盈亏额 四种指标
- **每月盈亏柱图**：正负堆叠柱状图
- **资产环形图**：按分组聚类 doughnut 图
- **紧凑 Hero**：滚动时吸附顶部的悬浮导航条

### 录入
- 月度快照批量录入，分组排列
- 账户 CRUD（新增/编辑/删除/归档），资金属性标签
- 分组管理（新增/重命名）

### 历史明细
- **列表视图** + **对照表视图**（账户 × 月份矩阵）
- 逐月盈亏/净流，正负色标

### 安全
- AES-GCM 端到端加密，Web Crypto API
- Passkey（WebAuthn PRF）/ 主密码 双解锁路径
- 主密钥缓存 localStorage，刷新免重登
- 云端数据全密文，D1 无法解密

### 备份
- 加密备份导出/导入
- 本地冷备份（File System Access API）
- localStorage 本地镜像，防云端误删

## 技术架构

```
index.html               ← 单文件 SPA（~6500 行）
worker/
├── index.js              ← Worker 路由分发
├── meta.js               ← 密钥元信息 CRUD（D1 meta 表）
├── vault.js              ← 加密账本 CRUD（D1 vault 表）
└── ping.js               ← 健康检查
```

- **Big.js**：CDN 加载，任意精度十进制运算
- **Chart.js 4.x**：CDN 加载，Percento 风格
- **双主题**：Apple 浅色 + Linear 深色，CSS 变量驱动
- **动效**：transitions.dev — 数字弹入、文本交换、面板浮现

## 文件结构

```
asset-ledger/
├── index.html                  ← 完整前端应用
├── worker/                     ← Cloudflare Worker API
├── wrangler.example.toml       ← 部署配置模板（fork 用）
├── .github/workflows/deploy.yml ← GitHub Actions 自动部署
├── package.json                ← 本地 `npm run deploy`
├── .gitignore
└── README.md
```

## 部署

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

Fork 本仓库。在 Settings → Secrets and variables → Actions 添加：

| Secret | 说明 |
|--------|------|
| `CLOUDFLARE_API_TOKEN` | API Token（My Profile → API Tokens → Workers 模板） |
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

## 开发

改 `index.html` 推送到 GitHub 自动部署。本地调试：

```bash
npx wrangler dev
```

## 安全模型

- 主密码 → PBKDF2（250K 迭代）→ 包装密钥 → 解开 AES-GCM 主密钥
- Passkey → WebAuthn PRF → HKDF → 包装密钥 → 同上
- 主密钥缓存在 localStorage，刷新免重登
- 数据传输和存储全程密文

## 已知边界

- D1 免费额度：5GB 存储 + 500 万次读/天 + 10 万次写/天
- 单用户设计
- Passkey PRF 需 Safari 18+ / Chrome 132+
- 本地冷备份需 Chromium（Chrome/Edge/Arc）
