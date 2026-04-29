# 个人资产负债表 · 财务驾驶舱

端到端加密的资产追踪系统。双主题（Apple 浅色 / Linear 深色），支持 TWR/XIRR 双轨收益分析，Cloudflare D1 云端同步 + 本地冷备份双路护航。

## 功能概览

### 首页 Dashboard
- **Hero 资产总览**：总资产/投资资产双视图切换，水位线透视资产分布（流动/投资/长期），点击 Hero 卡片打开资产明细抽屉
- **总资产曲线**：Percento 风格折线图，hover 十字准星 + 实时 scrubbing 联动 Hero 数值，Y 轴 ¥万标签，点击数据点钻取月度盈亏
- **收益率走势**：正负双色面积图（绿盈/红亏），零轴虚线，TWR / 简单加权 / XIRR / 盈亏额 四种指标切换，自定义时间区间
- **每月盈亏柱图**：市场盈亏 vs 净入金，自定义插件数值标签，点击钻取明细
- **资产环形图**：按分组聚类，点击查看分组内账户余额

### 录入
- 月度快照批量录入，自动沿用上月余额
- 输入防抖 + 事件委托，移动端 `inputmode="decimal"` 唤起纯数字键盘
- 草稿自动保存到 localStorage

### 历史明细
- **列表视图**：月度搜索、双月对比
- **对照表视图**：账户 × 月份矩阵透视，分组表头 + 黏性首列
- CSV 导出

### 账户钻取
- 每个账户的历史余额折线图
- 四维 KPI：累计盈亏 / 累计入金 / TWR / XIRR
- 逐月余额明细

### 安全
- AES-GCM 端到端加密，Web Crypto API
- Passkey（WebAuthn PRF）/ 主密码 双解锁路径
- 本地密钥缓存，刷新免重登
- 云端数据全密文，D1 数据库无法解密

### 备份
- 加密备份导出/导入
- 本地冷备份：授权浏览器文件夹后，每次保存自动写入加密备份
- localStorage 本地镜像，防云端误删

## 技术架构

```
index.html              ← 单文件 SPA（~6500 行）
└── functions/api/
    ├── meta.js         ← 密钥元信息 CRUD
    ├── vault.js        ← 加密账本 CRUD + 冲突检测
    └── ping.js         ← 健康检查
```

### 计算引擎
- **Big.js**：任意精度十进制运算，杜绝 IEEE 754 浮点误差
- **TWR**：时间加权收益率，逐月链乘
- **XIRR**：牛顿迭代法内部收益率，正负号校验 + NaN/Inf 保护
- **Dietz**：简易 Dietz 近似 TWR（账户钻取用）

### 设计系统
- 双主题：Apple 浅色（`#ffffff` / `#f5f5f7` / `#0071e3`）+ Linear 深色（`#08090a` / `#0f1011` / `#5e6ad2`）
- CSS 变量驱动，主题切换即时生效
- 图表：Chart.js 4.x，Percento 风格（隐藏 Y 轴网格、十字准星、hover-to-reveal 数据点、hero scrubbing），自定义插件（柱图数值标签、零线、十字线）
- 字体：Inter + JetBrains Mono（等宽数字）

## 文件结构

```
asset-ledger/
├── index.html              ← 完整前端应用
├── README.md
├── check-summary.html      ← 收益率组件视觉一致性检查页
└── functions/
    └── api/
        ├── meta.js
        ├── vault.js
        └── ping.js
```

## 部署步骤

### 1. 创建 D1 数据库

Cloudflare Dashboard → **Workers & Pages** → **D1 SQL Database** → **Create**

数据库名填 `asset-ledger-db`。创建后进入 Console 执行：

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

创建 Private 仓库，推送整个文件夹。

### 3. 创建 Pages 项目

**Workers & Pages** → **Create** → **Pages** → **Connect to Git** → 选择仓库 → 构建设置留空 → **Save and Deploy**

### 4. 绑定 D1

项目 → **Settings** → **Bindings** → **Add** → **D1 database**：
- Variable name: `DB`
- D1 database: `asset-ledger-db`

保存后 **Retry deployment**。

## 安全模型

- 主密码 → PBKDF2 → 包装密钥 → 解开 AES-GCM 主密钥
- Passkey → WebAuthn PRF → HKDF → 包装密钥 → 同上
- 主密钥缓存在 localStorage（`asset-ledger-key-v1`），刷新免重登
- 数据传输和存储全程密文，D1 端无法解密
- 本地镜像 + 冷备份均为加密格式

## 后续修改

推送 `index.html` 或 `functions/*.js` 到 GitHub，Cloudflare 自动部署。

## 已知边界

- D1 免费额度：5GB 存储 + 500 万次读/天 + 10 万次写/天，个人使用绰绰有余
- 单用户设计，多用户需改造接口加隔离
- 本地冷备份需 Chromium 内核浏览器（Chrome/Edge/Arc），Safari/Firefox 不支持 File System Access API
