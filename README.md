# Asset Ledger · 个人资产负债表

端到端加密的资产追踪系统。单文件 HTML SPA + Cloudflare Worker + D1，双主题（Apple 浅色 / Linear 深色），Chart.js + Big.js，GitHub Actions 自动部署。

## 功能概览

### 首页 Dashboard
- **Hero 资产总览**：总资产/投资资产双视图切换（排除债权和"其他资产"组），水位线透视资产分布（流动/投资/长期/负债率），点击 Hero 打开资产明细抽屉
- **总资产曲线**：Percento 风格折线图，hover 十字准星 + 实时 scrubbing 联动 Hero 数值
- **收益率走势**：累计收益率折线图，TWR / 简单加权 / XIRR / 盈亏额 四种指标切换
- **每月盈亏柱图**：正负堆叠柱状图，点击钻取明细
- **资产环形图**：按分组聚类 doughnut 图，点击查看分组内账户余额
- **紧凑 Hero**：滚动时吸附顶部的悬浮导航条，含视图切换

### 录入
- 月度快照批量录入，按分组排列账户行
- 账户 CRUD（新增/编辑/删除/归档），资金属性标签分类
- 分组管理（新增/重命名）
- 保存前冲突检测 + 云端回读校验 + 本地镜像

### 历史明细
- **列表视图**：月度总资产/盈亏/净流，正负色标
- **对照表视图**：账户 × 月份矩阵透视
- 一键刷新云端数据

### 安全
- AES-GCM 端到端加密，Web Crypto API
- Passkey（WebAuthn PRF）/ 主密码 双解锁路径
- 首次设置强制密码模式，系统内按需注册 Passkey
- 主密钥缓存 localStorage，刷新免重登
- 云端数据全密文，D1 无法解密

### 备份
- 加密备份导出/导入
- 本地冷备份（File System Access API）
- localStorage 本地镜像，防云端误删

## 技术架构

```
index.html               ← 单文件 SPA（~7400 行）
worker/
├── index.js              ← Worker 路由分发
├── meta.js               ← 密钥元信息 CRUD（D1 meta 表）
├── vault.js              ← 加密账本 CRUD + 冲突检测（D1 vault 表）
└── bg.js                 ← Bing 每日壁纸代理
```

- **Big.js**：CDN 加载，任意精度十进制运算
- **Chart.js 4.x**：CDN 加载，Percento 风格 + 自定义插件
- **双主题**：Apple 浅色 + Linear 深色，CSS 变量驱动
- **动效**：transitions.dev — 数字弹入、文本交换、面板浮现

## 文件结构

```
asset-ledger/
├── index.html                  ← 完整前端应用
├── worker/                     ← Cloudflare Worker API
├── wrangler.example.toml       ← 部署配置模板
├── .github/workflows/deploy.yml ← GitHub Actions 自动部署
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

## 安全模型

- 主密码 → PBKDF2（250K 迭代）→ 包装密钥 → 解开 AES-GCM 主密钥
- Passkey → WebAuthn PRF → HKDF → 包装密钥 → 同上
- 主密钥缓存在 localStorage，刷新免重登
- 数据全程密文传输和存储

## 已知边界

- D1 免费额度：5GB 存储 + 500 万次读/天 + 10 万次写/天
- 单用户设计
- Passkey PRF 需 Safari 18+ / Chrome 132+
- 本地冷备份需 Chromium（Chrome/Edge/Arc）
