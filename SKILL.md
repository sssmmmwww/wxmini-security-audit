---
name: wxmini-security-audit
description: 微信小程序全自动安全审计 Skill。使用 Agent Teams 编排 Agent，分阶段完成从反编译到报告生成的全流程静态安全分析。覆盖敏感信息泄露、API接口提取、加解密算法分析、漏洞分析四大维度。采用"脚本预扫描 + LLM智能分析"双层架构，脚本保证覆盖率，LLM保证准确率。
version: 1.0.0
tags: [security, wechat, miniprogram, audit, static-analysis]
platform: windows
tools_required:
  - unveilr.exe (内置于 tools/ 目录)
  - Python 3.x (系统环境，仅使用标准库)
  - grep / glob / view (CLI 内置)
  - create / edit (CLI 内置)
---

# Skill: wxmini-security-audit — 微信小程序安全审计

## 核心原则（所有 Agent 必须遵守）

1. **纯静态分析，严禁发送任何网络请求**
   - 禁止使用 curl、wget、fetch、Invoke-WebRequest 等工具发送任何 HTTP/HTTPS 请求
   - 禁止验证发现的密钥、Token、API 接口是否有效
   - 禁止连接任何数据库、Redis、消息队列等远程服务
   - 禁止下载或更新任何远程资源（npm 包信息、漏洞数据库等）
   - 所有分析必须且只能基于本地文件内容完成

2. **不生成任何攻击性代码**
   - 不生成 PoC（Proof of Concept）漏洞利用脚本
   - 不生成自动化攻击工具
   - 分析结果仅供安全审计和防御参考

3. **最小权限原则**
   - 仅读取 `{target_dir}` 下的源码文件
   - 仅在 `{output_dir}` 下写入分析结果文件
   - 不修改、不删除任何原有文件

4. **完整流程优先**
   - 必须完整执行 Phase 0 → Phase 1 → Phase 1.5 → Phase 2（全部4个Agent） → Phase 2.5（条件触发） → Phase 3 的标准分析流程
   - 不允许跳过、合并或改变任何阶段的执行顺序

## 编排铁律（Orchestrator 禁令，硬性约束）

> ⛔ 以下规则是不可违反的底线。违反任意一条等同于审计失败。

1. **严禁代劳** — Orchestrator 自身**严禁**直接创建任何 `*_analysis.json`、`*_report.json`、`security_report.md` 等输出文件。所有分析输出**必须且只能**由对应的子 Agent 生成。Orchestrator 唯一允许写入的文件是 Phase 1.5 中通过执行 Python 脚本间接生成的 `raw_*.json`。

2. **严禁跳阶段** — 每个 Phase 必须按序执行，不得以"已知结果"、"时间不够"、"Agent 太慢"为由跳过任何 Phase。Phase 2.5 的触发条件是 `custom_requests.has_custom_requests == true`，一旦满足，**必须启动 agent-07**，不得自行替代。

3. **严禁截留信息** — Orchestrator 在执行过程中获取的所有外部数据（Burp MCP 抓包数据、用户补充信息、其他 MCP 工具返回的数据）**必须完整传入**对应 Agent 的 prompt 中，不得仅留在 Orchestrator 上下文中。特别是 Phase 2.5 启动 agent-07 时，Burp 数据必须作为 prompt 的一部分传给 Agent。

4. **严禁提前终止** — 在等待 Phase 2 四个 Agent 返回期间，Orchestrator **禁止**分析代码、处理用户需求、生成任何结果。唯一允许的操作是等待和检查 Agent 完成状态。

5. **报告完整性** — Reporter Agent（agent-06）生成的输出中，**所有敏感信息发现和所有 API 接口必须被完整记录，严禁丢失任何数据**。主报告（`security_report.md`）中列出关键/高危发现，全量数据分别输出到独立文档（`api_endpoints_full.md` 和 `secrets_full.md`）。漏洞和加解密分析仍在主报告中完整展示。

## 描述
微信小程序全自动安全审计 Skill。使用 Agent Teams 编排多个 Agent，分阶段完成从反编译到报告生成的全流程静态安全分析。

**架构亮点**：
- **脚本 + LLM 双层架构**：Python 脚本通过正则保证 100% 规则覆盖率，LLM Agent 基于脚本结果做智能分析（误报过滤、BaseURL 关联、风险评级）
- **接口-文件映射**：按 JS 文件分组输出接口，LLM 可批量分析同一文件的所有发现
- **用户需求前置解析**：Phase 0 即解析用户特殊需求，Phase 2 完成后条件触发 CustomAnalyzer
- **支持外部工具集成**：可接收 Burp 等抓包工具的信息进行关联分析

覆盖维度：敏感信息泄露、API接口提取、加解密算法分析、漏洞分析。

## 触发方式
当用户请求分析微信小程序时触发。

- "帮我分析这个小程序 D:\wechat\miniapp\wxapkg_files"
- "审计这个小程序 C:\miniprogram\target"
- "分析一下这个微信小程序 {目录路径}"
- "帮我分析这个小程序 {目录路径}，重点看一下 /api/user/login 接口"
- "审计这个小程序 {目录路径}，Burp 抓包发现 /api/pay 接口的 amount 参数可以篡改"
- "分析这个小程序 {目录路径}，关注支付安全和越权风险"

从用户输入中提取 `{target_dir}`（小程序目录路径）。

## 变量定义

| 变量 | 含义 | 说明 |
|------|------|------|
| `{target_dir}` | 用户提供的小程序目录路径 | 从用户输入中提取，仅用于读取源码 |
| `{output_dir}` | 审计结果输出目录 | 在用户当前工作区下自动创建，所有分析输出文件写入此目录 |
| `{skill_dir}` | 本 Skill 的安装目录 | 即 `skill.md` 所在的目录路径，由编排器在运行时自动解析 |

**`{output_dir}` 创建规则**：在用户当前工作目录（CWD）下新建目录 `wxaudit-output`，即 `{output_dir}` = `{CWD}\wxaudit-output`。如果该目录已存在，则在名称后追加时间戳（如 `wxaudit-output-20240101-120000`）。所有 Agent 的分析结果文件、报告文件均输出到此目录，**不得写入 `{target_dir}`（源码目录）**。

**`{skill_dir}` 解析规则**：编排器（主 Agent）读取本 `skill.md` 时，取该文件所在目录的绝对路径作为 `{skill_dir}`。后续启动子 Agent 时，须将提示词中的 `{skill_dir}` 替换为实际路径。

## 工具依赖
- `unveilr.exe` — 位于 `{skill_dir}\tools\unveilr.exe`，用于反编译 wxapkg
- `endpoint_extractor.py` — 位于 `{skill_dir}\tools\scripts\endpoint_extractor.py`，用于正则提取接口
- `secret_scanner.py` — 位于 `{skill_dir}\tools\scripts\secret_scanner.py`，用于正则提取敏感信息
- `grep` / `glob` / `view` — 用于文件搜索和内容分析
- `create` / `edit` — 用于生成报告和JSON文件

## Agent 文件索引

所有 Agent 提示词文件位于 `{skill_dir}\agents\` 目录：

| Agent | 文件 | 阶段 | 职责 |
|-------|------|------|------|
| Decompiler | `agent-01-decompiler.md` | Phase 1 | 反编译与文件资产清单（支持多子目录） |
| SecretScanner | `agent-02-secret-scanner.md` | Phase 2 | 基于脚本结果的敏感信息智能分析 |
| EndpointMiner | `agent-03-endpoint-miner.md` | Phase 2 | 基于脚本结果的接口智能关联分析 |
| CryptoAnalyzer | `agent-04-crypto-analyzer.md` | Phase 2 | 加解密算法分析（纯LLM） |
| VulnAnalyzer | `agent-05-vuln-analyzer.md` | Phase 2 | 漏洞分析（七大维度，纯LLM） |
| Reporter | `agent-06-reporter.md` | Phase 3 | 报告生成 |
| CustomAnalyzer | `agent-07-custom-analyzer.md` | Phase 2.5 | 用户自定义需求深度分析（条件触发） |

## 执行流程

```
用户输入: "帮我分析这个小程序 {target_dir}，重点看支付接口"
        │
        ▼
┌─────────────────────────────────────┐
│  Phase 0: 需求解析（编排器自身完成）  │
│  · 提取 {target_dir}                │
│  · 创建 {output_dir}（CWD下新目录）  │
│  · 解析用户特殊需求 → custom_requests│
│  · 判断是否需要 CustomAnalyzer      │
│  不启动子Agent，编排器直接完成       │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 1: 反编译                     │
│  执行: agent-01-decompiler.md        │
│  · 扫描根目录及所有子目录            │
│  · 对每个含 wxapkg 的目录反编译      │
│  · 生成 file_inventory.json          │
│  阻塞: 必须完成后才进入 Phase 1.5   │
└──────────────┬──────────────────────┘
               │
               ▼
┌─────────────────────────────────────┐
│  Phase 1.5: 脚本预扫描                 │
│  编排器直接执行 Python 脚本:          │
│                                      │
│  1. python endpoint_extractor.py     │
│     → raw_endpoints.json             │
│                                      │
│  2. python secret_scanner.py         │
│     → raw_secrets.json               │
│                                      │
│  两个脚本串行执行（耗时通常<30s）    │
│  阻塞: 必须完成后才进入 Phase 2     │
└──────────────┬──────────────────────┘
               │
               ▼
┌───────────────────────────────────────────────────────────────────────┐
│  Phase 2: 并行分析（4 个 Agent 同时启动）                               │
│                                                                       │
│  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  ┌────────────────┐  │
│  │ SecretScanner  │  │ EndpointMiner  │  │ CryptoAnalyzer │  │ VulnAnalyzer   │  │
│  │ agent-02       │  │ agent-03       │  │ agent-04       │  │ agent-05       │  │
│  │                │  │                │  │                │  │                │  │
│  │ 输入:          │  │ 输入:          │  │ 输入:          │  │ 输入:          │  │
│  │ raw_secrets    │  │ raw_endpoints  │  │ file_inventory │  │ file_inventory │  │
│  │ .json          │  │ .json          │  │ (直接LLM分析)  │  │ (直接LLM分析)  │  │
│  │                │  │                │  │                │  │                │  │
│  │ 职责:          │  │ 职责:          │  │ 职责:          │  │ 职责:          │  │
│  │ ·误报过滤      │  │ ·BaseURL关联   │  │ ·加密逻辑分析  │  │ ·7维度漏洞     │  │
│  │ ·上下文判断    │  │ ·接口去重      │  │ ·密钥提取      │  │  分析          │  │
│  │ ·风险评级      │  │ ·方法推断      │  │ ·安全评估      │  │                │  │
│  │ ·可利用性评估  │  │ ·文件映射分组  │  │                │  │                │  │
│  │                │  │                │  │                │  │                │  │
│  │ → secrets_     │  │ → api_         │  │ → crypto_      │  │ → vuln_        │  │
│  │   report.json  │  │   endpoints.   │  │   analysis.    │  │   analysis.    │  │
│  │                │  │   json         │  │   json         │  │   json         │  │
│  └────────┬───────┘  └────────┬───────┘  └────────┬───────┘  └────────┬───────┘  │
│           │                   │                    │                   │          │
│  阻塞: 等待所有 4 个 Agent 完成                                        │          │
└───────────┼───────────────────┼────────────────────┼───────────────────┼──────────┘
            │                   │                    │                   │
            ▼                   ▼                    ▼                   ▼
┌───────────────────────────────────────────────────────────────────────┐
│  Phase 2.5: 用户自定义需求分析（条件触发）                             │
│                                                                       │
│  ⚠️ 仅当 Phase 0 检测到 custom_requests.has_custom_requests == true   │
│     时才执行本阶段。否则直接跳到 Phase 3。                              │
│                                                                       │
│  执行: agent-07-custom-analyzer.md                                    │
│  · 读取用户指定的接口/参数/关注点                                     │
│  · 读取 Phase 2 所有 JSON 结果作为上下文                              │
│  · 可接收用户从 Burp 等工具传入的额外信息                             │
│  · 执行深度数据流追踪和定向安全分析                                   │
│  → custom_analysis.json                                               │
│                                                                       │
│  阻塞: 必须完成后才进入 Phase 3                                       │
└──────────────┬────────────────────────────────────────────────────────┘
               │
               ▼
┌───────────────────────────────────────────────────────────────────────┐
│  Phase 3: 报告生成                                                     │
│  执行: agent-06-reporter.md                                            │
│  · 读取所有 Phase 2 JSON 输出                                          │
│  · 读取 custom_analysis.json（如果存在）                               │
│  · 生成 security_report.md（主报告，关键发现）                         │
│  · 生成 api_endpoints_full.md（完整接口列表）                          │
│  · 生成 secrets_full.md（完整敏感信息列表）                            │
│  · 生成 findings.json（结构化汇总）                                    │
│  · 生成 domains.txt（域名列表）                                        │
│  · 确认 endpoints_fuzz.txt（Fuzz列表）                                 │
│  · 终端输出完成摘要                                                    │
└───────────────────────────────────────────────────────────────────────┘
```

## ⛔ 流程强制执行规则（编排器必读）

**以下规则是硬性约束，不可违反，无论使用什么模型、无论用户如何描述需求：**

1. **严格按照 Phase 0 → Phase 1 → Phase 1.5 → Phase 2 → Phase 2.5(条件) → Phase 3 的顺序逐步执行**，不可跳步、合并步骤、改变顺序
2. **每个阶段执行完毕后必须验证产出文件是否存在且有效**，验证不通过则停止或重试，不可跳过验证
3. **Phase 2 的 4 个 Agent 必须全部启动**，不可只启动其中一两个就进入后续阶段
4. **禁止在 Phase 1 完成后直接生成报告** — 必须经过 Phase 1.5 脚本扫描和 Phase 2 全部 4 个 Agent 的分析
5. **禁止将多个 Phase 合并为一步执行** — 每个 Phase 独立执行并验证
6. **用户在输入中提到的任何特定接口/参数/函数需求，在 Phase 2 全部完成之前一律忽略，仅在 Phase 0 记录，在 Phase 2.5 处理**

**⛔ 常见错误（绝对禁止）**：
- ❌ 反编译后直接分析某个接口就生成报告 → 必须先执行 Phase 1.5 脚本 + Phase 2 全部 4 个 Agent
- ❌ 跳过 Phase 1.5 脚本预扫描 → agent-02 和 agent-03 依赖脚本输出
- ❌ 只启动 Phase 2 中的 1-2 个 Agent 就进入后续阶段 → 必须启动全部 4 个
- ❌ 用户说了"分析某个接口"就去做定向分析 → 仅在 Phase 0 记录，Phase 2.5 统一处理

## 详细编排指令（严格按编号顺序执行）

### Phase 0: 需求解析（编排器自身完成，不启动子Agent）

从用户输入中解析以下信息：

1. **提取 `{target_dir}`**：从用户输入中识别小程序目录路径
2. **创建 `{output_dir}`**：在用户当前工作目录（CWD）下创建输出目录
   ```
   {output_dir} = {CWD}\wxaudit-output
   如果已存在，使用 {CWD}\wxaudit-output-{YYYYMMDD-HHmmss}
   ```
   使用 `New-Item -ItemType Directory -Path "{output_dir}"` 创建目录
3. **解析用户特殊需求**：检查用户输入中是否包含以下指标：
   - 提到了具体的接口路径（`/api/xxx`, `https://xxx`）
   - 提到了具体的参数名（如 `token`, `amount`, `password`）
   - 提到了具体的函数名（如 `encrypt`, `login`）
   - 提到了"重点看"、"关注"、"分析一下"、"测试"等指示词
   - 提到了 Burp、抓包、请求、响应等外部工具信息
   - 提到了具体的安全关注点（如"SQL注入"、"越权"、"支付安全"等）

4. **生成 `custom_requests` 对象**（在内存中保存，不写文件）：

```json
{
  "has_custom_requests": true,
  "targets": [
    { "type": "endpoint", "value": "/api/pay/create", "context": "用户原文" },
    { "type": "parameter", "value": "amount", "context": "用户说 amount 可被篡改" },
    { "type": "focus_area", "value": "支付安全", "context": "用户关注支付安全" },
    { "type": "burp_info", "value": "POST /api/order 的 amount 参数", "context": "Burp 抓包发现" }
  ],
  "external_info": "用户提供的来自外部工具的额外信息"
}
```

如果用户没有任何特殊需求，设置 `has_custom_requests: false`，`targets: []`。

**Phase 0 不需要验证，直接进入 Phase 1。**

---

### Phase 1: 反编译

**读取** `agent-01-decompiler.md` 获取完整指令。

1. 检查 `{target_dir}` 目录是否存在
2. **递归扫描根目录及所有子目录**，检查是否有 `.wxapkg` 文件需要反编译
3. 对每个含 `.wxapkg` 的目录执行: `{skill_dir}\tools\unveilr.exe "{目录路径}"`
4. 汇总所有目录的扫描结果，生成 `file_inventory.json` 保存到 `{output_dir}`
5. 确认 JS 文件存在后进入 Phase 1.5

**加密 wxapkg 处理**: 如果反编译失败且错误信息提示文件已加密，向用户说明：
- PC 微信（3.9+版本）会对下载的 wxapkg 进行加密，需要先解密才能反编译
- 建议用户使用 `pc_wxapkg_decrypt` 等解密工具先解密，或从手机端（Android）获取未加密的 wxapkg
- 在报告中标注"该包为加密包，需解密后重新分析"

**失败处理**: 如果所有目录反编译均失败，向用户报告错误并终止。单个目录失败则继续处理其他目录。

**✅ Phase 1 验证（全部通过才能进入 Phase 1.5）**:
1. 检查 `{output_dir}\file_inventory.json` 是否已生成
2. 读取该文件前几行，确认 `total_files > 0`
3. 确认 JS 文件列表非空（有可分析的源码）
- **不通过** → 终止流程，向用户报告反编译失败原因。**不可跳过验证直接进入下一步。**
- **通过** → 继续 Phase 1.5

---

### Phase 1.5: 脚本预扫描

**编排器直接执行 Python 脚本**，不启动子 Agent。

依次执行以下两个脚本（串行，通常总耗时 < 30 秒）：

```
1. 接口提取:
   python "{skill_dir}\tools\scripts\endpoint_extractor.py" "{target_dir}" --output "{output_dir}"
   → 生成 {output_dir}\raw_endpoints.json

2. 敏感信息扫描:
   python "{skill_dir}\tools\scripts\secret_scanner.py" "{target_dir}" --output "{output_dir}"
   → 生成 {output_dir}\raw_secrets.json
```

**脚本功能说明**：
- `endpoint_extractor.py`：使用正则表达式提取所有接口（完整URL、路径片段、wx.request调用、云函数等），按文件分组输出，同时提取 BaseURL 候选值
- `secret_scanner.py`：使用正则表达式匹配所有敏感信息规则（密钥、Token、内网IP、个人信息等），初步过滤占位符，按文件分组输出

**脚本仅使用 Python 标准库**，不需要 pip install 任何包。

**✅ Phase 1.5 验证（全部通过才能进入 Phase 2）**:
1. 检查 `{output_dir}\raw_endpoints.json` 是否存在且非空
2. 检查 `{output_dir}\raw_secrets.json` 是否存在且非空
3. 读取每个文件的 `total_files_scanned` 字段，确认 > 0
- **不通过** → 检查 Python 是否可用（`python --version`），检查脚本是否存在，尝试重新执行。仍失败则向用户报告错误，但**不终止流程**——Phase 2 的 Agent 可以回退到纯 LLM 模式（自行 grep 扫描）
- **通过** → 继续 Phase 2

**⚠️ 降级策略**：如果脚本执行失败（Python 不可用等），Phase 2 的 SecretScanner 和 EndpointMiner 需回退到纯 LLM 模式（自行 grep 扫描）。在启动这两个 Agent 时，告知它们 `raw_*.json` 不存在，需要自行执行 grep 扫描。

---

### Phase 2: 并行分析（必须启动全部 4 个 Agent，缺一不可）

**同时启动 4 个 background Agent**，每个 Agent 读取对应的提示词文件执行任务：

```
Agent 2 (SecretScanner):
  - 读取 agent-02-secret-scanner.md 获取完整指令
  - 将 {target_dir} 和 {output_dir} 传入
  - 输入: {output_dir}\raw_secrets.json（脚本预扫描结果）+ {output_dir}\file_inventory.json
  - 源码读取: {target_dir}
  - 输出 {output_dir}\secrets_report.json

Agent 3 (EndpointMiner):
  - 读取 agent-03-endpoint-miner.md 获取完整指令
  - 将 {target_dir} 和 {output_dir} 传入
  - 输入: {output_dir}\raw_endpoints.json（脚本预扫描结果）+ {output_dir}\file_inventory.json
  - 源码读取: {target_dir}
  - 输出 {output_dir}\api_endpoints.json + {output_dir}\endpoints_fuzz.txt

Agent 4 (CryptoAnalyzer):
  - 读取 agent-04-crypto-analyzer.md 获取完整指令
  - 将 {target_dir} 和 {output_dir} 传入
  - 输入: {output_dir}\file_inventory.json（直接 LLM 分析源码）
  - 源码读取: {target_dir}
  - ⛔ 禁止将 custom_requests、用户指定的特定接口/参数等信息传入 agent-04 的 prompt
  - ⛔ agent-04 仅做通用全局加密分析，特定接口的加密分析由 agent-07 负责
  - 输出 {output_dir}\crypto_analysis.json

Agent 5 (VulnAnalyzer):
  - 读取 agent-05-vuln-analyzer.md 获取完整指令
  - 将 {target_dir} 和 {output_dir} 传入
  - 输入: {output_dir}\file_inventory.json（直接 LLM 分析源码）
  - 源码读取: {target_dir}
  - 输出 {output_dir}\vuln_analysis.json
```

**使用 `task` 工具**以 `mode="background"` 启动每个 Agent，类型使用 `general-purpose`。
在启动每个Agent时，必须先读取对应的agent提示词文件内容，将完整提示词包含在 `prompt` 参数中，并将 `{target_dir}` 和 `{skill_dir}` 替换为实际路径。

**⛔ Agent-04 隔离规则**：启动 Agent 4 (CryptoAnalyzer) 时，prompt 中**严禁包含**以下内容：
- 用户提到的特定接口路径（如 `/api/xxx`）
- 用户提到的特定参数名
- 来自 Burp 等外部工具的抓包信息
- `custom_requests` 对象或其任何内容
- 任何"重点分析"、"关注"等指向特定目标的指示

Agent-04 的 prompt 应仅包含：agent-04 提示词全文 + `{target_dir}` + `{output_dir}` + `{skill_dir}`。

**⛔ 等待指令：启动全部 4 个 Agent 后，你的唯一任务就是等待它们全部返回结果。在等待期间：**
- **禁止**分析任何代码
- **禁止**处理用户提到的任何特定接口或参数
- **禁止**生成任何报告或分析结果
- **禁止**启动任何其他 Agent
- **只做一件事：等待 4 个 Agent 全部完成**

等待所有 Agent 完成后，根据 Phase 0 的 `custom_requests` 判断进入 Phase 2.5 或直接进入 Phase 3。

**失败处理**: 如果某个 Agent 失败，记录失败原因，其他 Agent 的结果仍然可用。在后续阶段标注缺失的分析维度。

**✅ Phase 2 验证（全部通过才能进入下一阶段）**:
1. 检查以下 4 个文件的存在情况：
   - `{output_dir}\secrets_report.json`
   - `{output_dir}\api_endpoints.json`
   - `{output_dir}\crypto_analysis.json`
   - `{output_dir}\vuln_analysis.json`
2. 至少 3 个文件必须存在且非空（以 `{` 开头的有效 JSON）
3. 记录缺失的文件（对应 Agent 失败），供后续阶段标注
- **少于 3 个文件存在** → 终止流程，向用户报告 Phase 2 失败情况
- **3 个及以上存在** → 判断是否需要 Phase 2.5

---

### Phase 2.5: 用户自定义需求分析（条件触发）

> ⚠️ **仅当 Phase 0 解析的 `custom_requests.has_custom_requests == true` 时才执行本阶段。**
> 如果 `has_custom_requests == false`，直接跳到 Phase 3。

1. 读取 `{skill_dir}\agents\agent-07-custom-analyzer.md` 获取完整指令
2. 启动 CustomAnalyzer Agent（`general-purpose` 类型，`mode="background"`），传入：
   - `{target_dir}`（源码目录）
   - `{output_dir}`（输出目录）
   - `{custom_requests}` 对象（Phase 0 解析的用户需求）
   - **Orchestrator 获取的所有外部数据**（Burp 抓包数据等，必须完整传入，严禁截留）
   - Phase 2 所有 JSON 文件路径（位于 `{output_dir}`）
3. Agent 生成 `{output_dir}\custom_analysis.json`
4. 等待 Agent 完成

**✅ Phase 2.5 验证**:
1. 检查 `{output_dir}\custom_analysis.json` 是否存在
- **不通过** → 不影响已完成的标准审计（Phase 1-2 结果保留），向用户提示自定义分析未完成，继续 Phase 3
- **通过** → 继续 Phase 3

---

### Phase 3: 报告生成

**读取** `agent-06-reporter.md` 获取完整指令。

1. 确认 Phase 2 的 JSON 输出文件存在情况（位于 `{output_dir}`）
2. 确认 `custom_analysis.json` 是否存在（Phase 2.5 产出，可选）
3. 将 `has_custom_requests` 标志传给 Reporter Agent（用于质检）
4. 启动 Reporter Agent（`general-purpose` 类型），传入完整提示词
5. 输入为 `{output_dir}` 下所有可用的 JSON 文件 + `custom_analysis.json`（如果存在）
6. 生成最终报告和辅助文件到 `{output_dir}`
7. 在终端输出完成摘要

**✅ Phase 3 验证（全部通过才视为流程完成）**:
1. 检查 `{output_dir}\security_report.md` 是否存在且大小 > 1KB
2. 检查 `{output_dir}\api_endpoints_full.md` 是否存在
3. 检查 `{output_dir}\secrets_full.md` 是否存在
4. 检查 `{output_dir}\findings.json` 是否存在
5. 检查 `{output_dir}\domains.txt` 是否存在
6. 检查 `{output_dir}\endpoints_fuzz.txt` 是否存在
- **不通过** → 重新执行一次 Reporter Agent（最多重试 1 次），仍不通过则向用户提示报告生成失败
- **通过** → 审计流程完成，输出摘要

## 输出文件清单

分析完成后，`{output_dir}` 目录下将包含以下输出文件：

| 文件 | 格式 | 来源 | 说明 |
|------|------|------|------|
| `file_inventory.json` | JSON | Decompiler (Phase 1) | 文件资产清单 |
| `raw_endpoints.json` | JSON | Python脚本 (Phase 1.5) | 接口正则提取原始结果（按文件分组） |
| `raw_secrets.json` | JSON | Python脚本 (Phase 1.5) | 敏感信息正则提取原始结果（按文件分组） |
| `secrets_report.json` | JSON | SecretScanner (Phase 2) | 敏感信息智能分析结果 |
| `api_endpoints.json` | JSON | EndpointMiner (Phase 2) | 接口智能分析结果（含文件映射） |
| `endpoints_fuzz.txt` | TXT | EndpointMiner (Phase 2) | Fuzz接口列表 |
| `crypto_analysis.json` | JSON | CryptoAnalyzer (Phase 2) | 加解密分析结果 |
| `vuln_analysis.json` | JSON | VulnAnalyzer (Phase 2) | 漏洞分析结果 |
| `custom_analysis.json` | JSON | CustomAnalyzer (Phase 2.5) | 用户自定义需求分析结果（可选） |
| `security_report.md` | Markdown | Reporter (Phase 3) | **最终安全审计报告（主报告）** |
| `api_endpoints_full.md` | Markdown | Reporter (Phase 3) | 完整接口列表（独立文档） |
| `secrets_full.md` | Markdown | Reporter (Phase 3) | 完整敏感信息列表（独立文档） |
| `findings.json` | JSON | Reporter (Phase 3) | 汇总结构化数据 |
| `domains.txt` | TXT | Reporter (Phase 3) | 域名列表 |

> ⚠️ 所有输出文件位于 `{output_dir}`（用户当前工作区下的 `wxaudit-output` 目录），**不在 `{target_dir}`（源码目录）中**。

## 错误处理策略

| 错误场景 | 处理方式 |
|----------|----------|
| 目录不存在 | 提示用户检查路径，终止 |
| 反编译失败（全部目录） | 报告错误原因，终止 |
| 反编译失败（部分目录） | 记录失败目录，继续处理成功的目录 |
| 无 JS 文件 | 提示可能不是小程序目录，终止 |
| Python 不可用 | Phase 1.5 脚本失败，Phase 2 Agent 回退到纯 LLM 模式 |
| 脚本执行失败 | 同上，记录错误，不终止流程 |
| 单个 Phase 2 Agent 失败 | 记录错误，其他 Agent 继续，报告标注缺失维度 |
| Phase 2.5 CustomAnalyzer 失败 | 不影响已完成的标准审计，向用户提示 |
| Phase 3 Reporter Agent 失败 | 尝试重试一次，仍失败则输出已有的 JSON 结果 |
| 用户指定的分析目标在代码中未找到 | 在 `custom_analysis.json` 中记录"未找到"状态 |

## 大文件处理策略

所有 Phase 2 Agent 在扫描时须遵循以下策略，防止大文件导致超时或上下文溢出：

| 文件大小 | 处理方式 |
|----------|----------|
| ≤ 200KB | 可直接读取全文分析 |
| 200KB ~ 500KB | 优先使用 grep 按模式搜索，必要时分段读取 |
| 500KB ~ 1MB | **仅使用 grep** 搜索特定模式，不读取全文 |
| > 1MB | 仅 grep 搜索高优先级模式（Critical/High），跳过 Info 级别扫描 |

**通用原则**：
- 遇到 webpack 打包的单文件（如 `app-service.js`），优先 grep 提取目标模式而非全文阅读
- 在输出 JSON 中标注 `large_files_skipped` 字段，记录因文件过大而降级处理的文件列表
- 优先保证 Critical/High 级别发现的覆盖率，Info 级别可降级
- **Phase 1.5 的 Python 脚本已内置大文件处理**：>2MB 的文件会被跳过并记录

## 覆盖率要求
- JS 文件扫描覆盖率 ≥ 95%（Python 脚本保证基础覆盖率）
- JSON 配置文件扫描覆盖率 = 100%
- 每个 Agent 在输出中记录实际扫描覆盖率
- 脚本预扫描的覆盖率在 `raw_*.json` 的 `total_files_scanned` 中记录
