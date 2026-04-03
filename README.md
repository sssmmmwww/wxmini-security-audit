# 🔒 wxmini-security-audit

**微信小程序全自动安全审计 Skill** — 基于 Claude Code Agent Teams 的多智能体协作安全分析框架

> 用户只需提供小程序目录路径，Skill 自动完成从反编译到生成完整安全报告的全流程。

---

## ✨ 特性

- 🤖 **7 Agent 协作** — 反编译、敏感信息扫描、接口提取、加密分析、漏洞挖掘、自定义分析、报告生成，各司其职
- ⚡ **脚本 + LLM 双层架构** — Python 正则保证 100% 规则覆盖率，LLM 做智能分析（误报过滤、风险评级、上下文关联）
- 🔄 **Phase 2 四路并行** — 4 个分析 Agent 同时启动，大幅缩短审计耗时
- 🎯 **用户需求前置解析** — 支持指定重点接口、参数、安全关注点，Phase 2.5 自动触发深度定向分析
- 🔗 **外部工具集成** — 可接收 Burp Suite 等抓包工具信息进行关联分析
- 📊 **双层报告输出** — 主报告聚焦关键发现 + 独立文档保留全量数据，兼顾可读性与完整性
- 🛡️ **纯静态分析** — 全程零网络请求，不生成攻击代码，安全合规

## 📋 覆盖维度

| 维度 | 负责 Agent | 说明 |
|------|-----------|------|
| 敏感信息泄露 | SecretScanner (agent-02) | 硬编码密钥/Token、内网IP、个人信息、调试信息等 |
| API 接口提取 | EndpointMiner (agent-03) | 完整URL、路径片段、wx.request 调用、云函数、BaseURL 关联 |
| 加解密算法分析 | CryptoAnalyzer (agent-04) | 加密逻辑、密钥管理、算法安全性评估 |
| 漏洞分析 | VulnAnalyzer (agent-05) | 七大维度：认证鉴权、数据安全、注入、越权、支付、信息泄露、配置安全 |
| 自定义需求分析 | CustomAnalyzer (agent-07) | 用户指定的特定接口/参数深度分析（条件触发） |

## 🏗️ 架构

```
用户输入: "帮我分析这个小程序 {target_dir}"
         │
         ▼
┌─────────────────────────────────────┐
│  Phase 0: 需求解析                   │  编排器自身完成
│  提取路径 → 创建输出目录 → 解析需求  │  不启动子 Agent
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 1: 反编译                     │  agent-01
│  扫描子目录 → unveilr 反编译         │  → file_inventory.json
│  → 生成文件资产清单                  │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 1.5: 脚本预扫描               │  编排器执行 Python 脚本
│  endpoint_extractor.py → 接口提取    │  → raw_endpoints.json
│  secret_scanner.py → 敏感信息扫描    │  → raw_secrets.json
└──────────────┬──────────────────────┘
               │
               ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 2: 并行分析（4 Agent 同时启动）                          │
│                                                               │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐ │
│  │SecretScanner │ │EndpointMiner │ │CryptoAnalyzer│ │ VulnAnalyzer │ │
│  │  agent-02    │ │  agent-03    │ │  agent-04    │ │  agent-05    │ │
│  │              │ │              │ │              │ │              │ │
│  │ 脚本结果     │ │ 脚本结果     │ │ 纯LLM分析    │ │ 纯LLM分析    │ │
│  │ + LLM分析    │ │ + LLM分析    │ │              │ │              │ │
│  └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ └──────┬───────┘ │
│         │                │                │                │         │
│  等待全部 4 个 Agent 完成                                     │         │
└─────────┼────────────────┼────────────────┼────────────────┼─────────┘
          │                │                │                │
          ▼                ▼                ▼                ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 2.5: 自定义需求分析（条件触发）       agent-07          │
│  仅当用户指定了特定接口/参数时触发                             │
│  → custom_analysis.json                                       │
└──────────────┬────────────────────────────────────────────────┘
               │
               ▼
┌───────────────────────────────────────────────────────────────┐
│  Phase 3: 报告生成                           agent-06          │
│  汇总所有分析结果 → 生成主报告 + 独立文档 + 结构化数据          │
│  → security_report.md / api_endpoints_full.md / secrets_full.md│
│  → findings.json / domains.txt / endpoints_fuzz.txt            │
└───────────────────────────────────────────────────────────────┘
```

## 📁 项目结构

```
wxmini-security-audit/
├── SKILL.md                          # 主编排文件（Orchestrator 指令）
├── README.md                         # 项目说明
├── agents/                           # Agent 提示词文件
│   ├── agent-01-decompiler.md        # Phase 1  反编译与资产清单
│   ├── agent-02-secret-scanner.md    # Phase 2  敏感信息智能分析
│   ├── agent-03-endpoint-miner.md    # Phase 2  接口智能关联分析
│   ├── agent-04-crypto-analyzer.md   # Phase 2  加解密算法分析
│   ├── agent-05-vuln-analyzer.md     # Phase 2  漏洞分析（七大维度）
│   ├── agent-06-reporter.md          # Phase 3  报告生成
│   └── agent-07-custom-analyzer.md   # Phase 2.5 用户自定义需求分析
└── tools/                            # 工具与脚本
    ├── unveilr.exe                   # wxapkg 反编译工具
    └── scripts/
        ├── endpoint_extractor.py     # 接口正则提取脚本
        └── secret_scanner.py         # 敏感信息正则扫描脚本
```

## 🚀 使用方法

### 前置条件

| 依赖 | 说明 |
|------|------|
| [Claude Code](https://docs.anthropic.com/en/docs/claude-code) | Claude Code CLI 环境（支持 Agent Teams / Skill） |
| Python 3.x | 系统已安装，仅使用标准库，无需 pip install |
| Windows | 当前版本依赖 Windows 平台（unveilr.exe） |

### 安装

将本项目克隆或下载到本地，放入 Claude Code 的 Skill 目录即可：

```bash
git clone https://github.com/sssmmmwww/wxmini-security-audit.git
```

克隆后需自行获取 `unveilr.exe`（微信小程序反编译工具）并放入 `tools/` 目录：

```
tools/
└── unveilr.exe    ← 需自行放置
```

> `unveilr` 为第三方开源工具，可从 [unveilr 项目](https://github.com/nicholaschan23/unveilr) 获取。

### 运行

在 Claude Code 中直接向 AI 发出指令：

```
帮我分析这个小程序 D:\wechat\miniapp\wxapkg_files
```

支持多种触发方式：

```
# 基础审计
审计这个小程序 C:\miniprogram\target

# 指定重点关注（自动触发 Phase 2.5 深度分析）
帮我分析这个小程序 D:\wxapp，重点看一下 /api/user/login 接口

# 携带 Burp 抓包信息
分析这个小程序 D:\wxapp，Burp 抓包发现 /api/pay 接口的 amount 参数可以篡改

# 指定安全关注点
分析这个小程序 D:\wxapp，关注支付安全和越权风险
```

### 输出

审计完成后，在当前工作目录下生成 `wxaudit-output/` 文件夹，包含：

| 文件 | 格式 | 说明 |
|------|------|------|
| `security_report.md` | Markdown | **主报告** — 关键/高危发现、风险评估、修复建议 |
| `api_endpoints_full.md` | Markdown | 完整接口列表（请求方式、BaseURL、路径、来源文件） |
| `secrets_full.md` | Markdown | 完整敏感信息列表（有效发现 + 误报项） |
| `findings.json` | JSON | 结构化汇总数据 |
| `domains.txt` | TXT | 提取的域名列表 |
| `endpoints_fuzz.txt` | TXT | 可用于 Fuzz 测试的接口列表 |
| `file_inventory.json` | JSON | 反编译后文件资产清单 |
| `raw_endpoints.json` | JSON | 接口正则提取原始结果 |
| `raw_secrets.json` | JSON | 敏感信息正则提取原始结果 |
| `secrets_report.json` | JSON | 敏感信息智能分析结果 |
| `api_endpoints.json` | JSON | 接口智能分析结果 |
| `crypto_analysis.json` | JSON | 加解密分析结果 |
| `vuln_analysis.json` | JSON | 漏洞分析结果 |
| `custom_analysis.json` | JSON | 自定义需求分析结果（可选） |

## 🛡️ 安全原则

本 Skill 严格遵循以下安全约束：

1. **纯静态分析** — 禁止发送任何网络请求，禁止验证密钥/Token 有效性，所有分析仅基于本地文件
2. **不生成攻击代码** — 不生成 PoC 漏洞利用脚本或自动化攻击工具，仅供安全审计和防御参考
3. **最小权限** — 仅读取源码目录，仅在输出目录写入分析结果，不修改不删除原有文件
4. **数据不外传** — 分析数据全程在本地处理，不上传到任何第三方服务

## ⚙️ 技术细节

### 双层架构

```
         ┌──────────────────────────────────┐
         │        Python 脚本层              │
         │   正则匹配 → 100% 规则覆盖率      │
         │   endpoint_extractor.py          │
         │   secret_scanner.py              │
         └──────────────┬───────────────────┘
                        │ raw_*.json
                        ▼
         ┌──────────────────────────────────┐
         │          LLM Agent 层             │
         │   智能分析 → 高准确率             │
         │   误报过滤 / BaseURL关联          │
         │   风险评级 / 上下文判断            │
         └──────────────────────────────────┘
```

- **脚本层**：使用 Python 标准库的正则表达式，逐文件扫描所有 JS/JSON 文件，保证不遗漏任何匹配项
- **LLM 层**：基于脚本原始结果做二次分析，过滤误报（占位符、注释、示例代码），关联上下文（BaseURL 拼接、同文件聚合），输出可读报告

### 降级策略

如果 Python 不可用导致脚本执行失败，Phase 2 的 SecretScanner 和 EndpointMiner 会自动回退到纯 LLM 模式（自行 grep 扫描），保证审计流程不中断。

### 大文件处理

| 文件大小 | 处理方式 |
|----------|----------|
| ≤ 200KB | 直接读取全文分析 |
| 200KB ~ 500KB | 优先 grep 按模式搜索 |
| 500KB ~ 1MB | 仅 grep 搜索特定模式 |
| > 1MB | 仅搜索 Critical/High 级别模式 |

### 加密包处理

如果遇到加密的 wxapkg（PC 微信 3.9+ 版本），Skill 会提示用户先使用解密工具处理，或从 Android 端获取未加密的包。

## 📝 注意事项

- 当前版本仅支持 **Windows** 平台（反编译工具 `unveilr.exe` 为 Windows 可执行文件）
- Python 脚本仅使用标准库，无需额外安装依赖
- 输出目录自动创建在当前工作区下，不会污染源码目录
- 如目标目录已是反编译后的源码（无 wxapkg），Phase 1 会跳过反编译步骤，直接生成资产清单

## 📄 License

MIT License

---

> 本项目仅供安全研究与合法授权测试使用，使用者需遵守相关法律法规。
