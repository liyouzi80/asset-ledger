# 资产账本 · Cloudflare 部署版

云端同步 + 端对端加密。所有数据在浏览器加密后才上传，Cloudflare 上看到的全是密文。

## 文件结构

```
asset-tracker-final/
├── index.html              ← 前端页面
└── functions/
    └── api/
        ├── meta.js         ← 处理 /api/meta（密钥元信息）
        ├── vault.js        ← 处理 /api/vault（加密的账本数据）
        └── ping.js         ← 健康检查
```

## 部署步骤

### 1. 创建 D1 数据库（如果之前没建过）

Cloudflare Dashboard → **Workers & Pages** → **D1 SQL Database** → **Create**

数据库名填 `asset-ledger-db`。

创建后进入数据库 → **Console** → 执行：

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

### 2. 推送到 GitHub

在 GitHub 创建一个 **Private** 仓库（比如名为 `asset-ledger`），把这整个文件夹的内容推送上去。

最简单的方式：在 GitHub 网页直接上传整个文件夹（Add file → Upload files → 把文件全部拖进去）。

### 3. 删除旧 Pages 项目（如果之前用 Direct Upload 建过）

Cloudflare → **Workers & Pages** → 找到旧的 `asset-ledger` 项目 → 设置里删掉。

### 4. 创建新 Pages 项目（连接 GitHub）

**Workers & Pages** → **Create** → **Pages** → **Connect to Git**

- 授权 GitHub
- 选择刚才创建的仓库
- 项目名：`asset-ledger`
- 构建设置全部留空（这是纯静态项目）
- 点 **Save and Deploy**

### 5. 绑定 D1 数据库

部署完成后，进入项目 → **Settings** → **Bindings** → **Add** → **D1 database**：

- Variable name: `DB`（必须是大写 DB）
- D1 database: 选 `asset-ledger-db`

保存。然后到 **Deployments** 页，点最近一次部署旁的 ⋮ → **Retry deployment**，让绑定生效。

### 6. 删除旧 Worker（如果之前建过 asset-ledger-api）

不再需要单独的 Worker，可以删掉。

## 完成

访问 `https://你的项目名.pages.dev`，第一次会要求设置主密码或注册 Passkey。

之后任何设备打开这个地址，输入密码 / 用 Touch ID，都能看到同步的最新数据。

## 数据安全模型

- **浏览器**：用主密码 PBKDF2 派生 AES-GCM 密钥（或用 Passkey PRF 派生），加密所有数据
- **网络**：传输的是密文 + IV
- **D1 数据库**：存储的是密文。即使数据库泄露，没有你的密码无法解密

## 后续修改

改了 `index.html` 或 `functions/*.js` 后，推到 GitHub，Cloudflare 自动重新部署。

## 已知边界

- D1 免费额度：5GB 存储 + 每天 500 万次读 + 10 万次写。这个应用一辈子也用不完
- 单用户使用。多用户场景需要改造接口加用户隔离
- 重置数据后，旧的备份依然可以用（但导入会覆盖当前数据）
