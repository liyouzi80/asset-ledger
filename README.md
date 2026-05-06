# Asset Ledger（个人资产负债表）

> 端到端加密的个人资产负债表 — 跨券商、跨银行、跨币种的净值全景。
> **数据由你掌控，服务器只能看到密文。**

[![vanilla JS](https://img.shields.io/badge/vanilla-JS-blue)](https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API)
[![AES-256-GCM](https://img.shields.io/badge/E2E-AES--256--GCM-green)](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
[![deploy](https://img.shields.io/badge/deploy-Cloudflare%20Workers-orange)](https://workers.cloudflare.com/)
[![license](https://img.shields.io/badge/license-MIT-brightgreen)](./LICENSE)

---

## 它是什么

一个**只为你自己用**的资产记账工具。每月手动录入各账户余额，自动计算总资产、市场盈亏、收益率。所有数据在浏览器里加密后才上传，服务器只看到密文——即便数据库被脱库，没有你的密码或 Passkey，也无法解密。

适合谁：
- 跨券商 / 跨银行 / 跨币种的个人投资者
- 不想把财务数据交给第三方 App 的人
- 喜欢"自己的数据自己管"的工程师

不适合：
- 需要多人协作的家庭账本
- 需要自动同步交易明细的高频交易者
- 不愿意每月花 5 分钟手动录入的人

---

## 核心特性

| 安全 | Dashboard | 录入 | 历史 |
|:--|:--|:--|:--|
| 主密码 / Passkey 双解锁 | Hero 巨幅资产 + 月对月变化 | 月度快照批量录入 | 列表 + 矩阵双视图 |
| PBKDF2 250K → AES-256-GCM | KPI 三连：盈亏 / 净流 / 年内 | 一键复制上月数据 | TWR / 简单 / XIRR 三种收益率 |
| 服务端全程零明文 | 收益率走势 + 期间切换 | 账户 CRUD + 分组管理 | 月份比较 + 异常变化提醒 |
| 浏览器本地镜像备份 | 资产分布饼图 + 钻取 | 写入回读校验 | CSV 导出 + 断月检测 |

---

## 架构

```
┌─────────────────────────────────────────────┐
│  浏览器                                      │
│  ┌─────────────────────────────────────┐    │
│  │  index.html  (单文件 SPA · 零框架)  │    │
│  │  ├─ css/variables.css   (主题变量)  │    │
│  │  ├─ css/app.css         (基础样式)  │    │
│  │  └─ css/theme-suba.css  (素白主题)  │    │
│  └────────────────┬────────────────────┘    │
│                   │                          │
│  ┌────────────────▼────────────────────┐    │
│  │  Web Crypto API                      │    │
│  │  · AES-256-GCM  encrypt / decrypt    │    │
│  │  · PBKDF2 250K  deriveKey            │    │
│  │  · WebAuthn PRF passkey unlock       │    │
│  └────────────────┬────────────────────┘    │
└───────────────────┼─────────────────────────┘
                    │  { iv, cipher } 密文
                    ▼
┌─────────────────────────────────────────────┐
│  Cloudflare Workers                          │
│  · /api/vault  存取加密账本                  │
│  · /api/meta   存取认证信息                  │
│  · /api/bg     背景图代理                    │
│  · 写入回读校验 + 缓存禁用                    │
└────────────────┬────────────────────────────┘
                 │
                 ▼
┌─────────────────────────────────────────────┐
│  Cloudflare D1 (SQLite)                      │
│  · vault 表  加密 payload 存储                │
│  · meta 表   salt + verifier + 包装密钥       │
│  · 7 天 Time Travel 自动备份                  │
└─────────────────────────────────────────────┘
```

| 层 | 技术 |
|:--|:--|
| 前端 | Vanilla JS · 单文件 SPA · 零构建工具链 |
| 加密 | Web Crypto API · AES-256-GCM · PBKDF2 250K · WebAuthn PRF |
| 图表 | Chart.js 4.x · 折线 + 饼图 + 柱状 · 自定义十字准星 |
| 运算 | Big.js · 任意精度十进制（避免浮点误差）|
| 后端 | Cloudflare Workers · 5 文件 |
| 数据库 | Cloudflare D1（SQLite）· 键值模式 |
| 主题 | Apple 浅色 · 素白 · Linear 深色 · CSS 变量驱动 |
| 部署 | GitHub Actions → `wrangler deploy` · push 即上线 |

---

## 部署

**3 步上线：**

| # | 操作 | 说明 |
|:-:|:--|:--|
| 1 | 创建 D1 数据库 | Cloudflare Dashboard → D1 → 执行 [建表 SQL](#建表-sql) |
| 2 | 设置 GitHub Secrets | `CLOUDFLARE_API_TOKEN` · `CLOUDFLARE_ACCOUNT_ID` · `D1_DATABASE_ID` |
| 3 | `git push main` | GitHub Actions 触发 `wrangler deploy` |

### 本地开发

```bash
# 1. 克隆仓库
git clone https://github.com/<你的用户名>/asset-ledger.git
cd asset-ledger

# 2. 配置 wrangler
cp wrangler.example.toml wrangler.toml
# 编辑 wrangler.toml，填入你的 D1 database_id

# 3. 启动本地服务（默认 http://localhost:8787）
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

---

## 安全模型

### 加密链路

```
用户输入                  浏览器                      网络                    服务器
   │                        │                          │                       │
   │ 主密码 / Passkey  ─────▶│                          │                       │
   │                        │ PBKDF2 250K              │                       │
   │                        │ → 包装密钥                │                       │
   │                        │ ↓                        │                       │
   │                        │ 主密钥 (AES-256)          │                       │
   │                        │ ↓ 加密                    │                       │
   │                        │ { iv, cipher } ──────────▶│ HTTPS ──────────────▶│ D1 存储密文
   │                        │                          │                       │
   │                        │◀── { iv, cipher } ───────│◀──────────────────────│ 取回密文
   │                        │ ↓ 解密                    │                       │
   │ 看到自己的数据  ◀──────│                          │                       │
```

**关键点：**

- 主密钥**永不离开浏览器**——它是用主密码或 Passkey PRF 派生出来的，没有原始凭证就生成不出来
- 服务器只看到 `{ iv: "...", cipher: "...base64..." }`——即便整个 D1 数据库被泄露，密文仍然不可解
- Passkey PRF 是 WebAuthn 扩展，密钥派生发生在硬件层（Mac 的 Secure Enclave / iPhone 的 Secure Element / Windows Hello），**无法被恶意软件读取**

### 三道防覆盖防线

为了防止"加密数据被错误覆盖永久丢失"这种灾难：

1. **本地镜像**：每次解锁/保存时，浏览器 localStorage 留一份当前 vault 的加密副本
2. **写入回读校验**：每次保存后从 D1 读回比对 IV，不一致就抛错
3. **首次注册前检查**：检测到 D1 空但本地有镜像时，禁止"创建新账本"，强制走"从镜像恢复"

---

## 边界

- **D1 免费额度**：5GB 存储 / 每天 500 万次读 / 每天 10 万次写 — 个人使用绰绰有余
- **单用户设计**：所有数据用同一组凭证加密，不支持多用户隔离
- **Passkey PRF 浏览器要求**：Safari 18+ / Chrome 132+ / Edge 132+
- **加密 API 要求**：HTTPS 或 localhost（Web Crypto 不在 HTTP 下工作）
- **手动录入颗粒度**：月度快照（更细颗粒度需要对接券商 API，本工具不做这件事）

---

## 数据管理

### 备份

页脚的 `导出加密备份` 会下载一个 `.json` 文件——内容是密文。即便你把它发到任何地方，没有主密码也解不开。建议定期：

- 每次大幅录入数据后导出一份
- 保存到 iCloud Drive / OneDrive / Google Drive 任意一个

### 恢复

通过页脚的 `导入加密备份` 上传 `.json` 文件，配合主密码或 Passkey 即可还原。

### 数据迁移

vault 在浏览器解密后是一个 JSON 对象，结构稳定（accounts / snapshots / groupOrder），可以：

- 通过浏览器控制台 `console.log(state)` 导出明文
- 用脚本批量处理后再加密回写

---

## 致谢

- **Cloudflare Workers + D1** — 免费的边缘计算 + SQLite，是这个项目能存在的物理基础
- **Chart.js** — 唯一的运行时依赖
- **Big.js** — 处理金融小数的最佳工具
- **WebAuthn PRF 规范** — 让 Passkey 不仅是认证手段、也能派生加密密钥

---

## License

MIT
