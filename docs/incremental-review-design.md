# 增量代码检视（Incremental PR/MR Review）设计方案

> 状态：**Phase 1 已实现**（未发布版本，`go build` / `go test` 全绿）
> 目标：在现有 sgre 引擎之上，端到端支持 `/secguard diff` / `/secguard pr` / `/secguard mr` 的增量检视，
> 且**绝不影响**现有全仓扫描（承重功能）。

---

## 1. 背景与目标

工程师日常：开发 → commit → 提 PR/MR → 只想对**这次改动**做安全检视，而不是把全仓再扫一遍、再被一堆历史存量问题淹没。

期望命令：

```bash
/secguard git diff HEAD~1      # 显式 diff
/secguard pr                   # 自动 merge-base 到 HEAD
/secguard mr                   # pr 的别名（GitLab）
```

硬性约束：

1. **不影响全仓扫描** —— 这是承重功能，任何改动必须向后兼容，增量路径默认关闭、物理隔离。
2. **端到端** —— git diff → 引擎扫描 → AI 分类 → 报告，一条链路走通。
3. **重复执行友好** —— 反复 push / 反复跑命令 / 修了再提交，都要幂等、可去重、不重复上报已处理的问题。

---

## 2. 业界做法调研

增量检视业界有两种主流思路，**侧重点不同、可叠加**：

### 2.1 「新问题」判定（baseline diff）—— 安全工具的标准做法

- **Semgrep CI**：`--baseline-commit <merge-base>`，只报告「基线里不存在、且落在变更行上」的新问题。
- **CodeQL / GitHub code scanning**：PR 视角，在 merge-base 处对比，只报新 alert。
- **SonarQube**：「New Code = PR diff」，「New Issues = 只在新代码行上的问题」。

共性：**定位到「行」级别**，用「基线 + 变更行」双重过滤来定义「新问题」。这正是安全检视要交付的东西——不是「哪些文件变了」，而是「哪些新漏洞被这次改动引入了」。

### 2.2 「影响半径」（blast radius）—— code-review-graph 的做法

参考项目 [code-review-graph](https://github.com/tirth8205/code-review-graph/) 的核心：

1. Tree-sitter 解析 AST → 存成知识图（节点：函数/类/import；边：调用/继承/测试覆盖）。
2. **增量更新**：`git diff` 找变更文件，通过图边找依赖方，只对 SHA-256 变化的文件重解析。
3. **Blast radius**：文件变了 → 沿图追溯所有 caller / dependent / test，得到「受影响最小集合」。
4. AI 只读这个最小集合，不读全仓。

它解决的是**通用代码评审的 token 浪费**，输出是「受影响文件/函数集合」，**不定位到行**、也不做「新问题」判定。

### 2.3 结论：两者结合，落地到 sgre 已有的语义图

sgre 已经具备 code-review-graph 图能力的等价物：

- `CALL` / `DATA_FLOW` / `GLOBAL_ACCESS` / `LOCK_ORDER` 边（`db/schema.go` graph_edges 枚举）。
- 多源图遍历 `ReachableFromEntries`（`db/store.go`）—— 一步到位算出「受影响函数」。
- 候选已带 `SourceLine`（`planner/evidence_package.go` 的 `EvidenceItem.SourceLine`）—— flow 型漏洞的源头行号。

因此方案定为：

- **主路径（Phase 1）**：baseline diff —— 定位到「变更行上的新问题」（业界安全标准）。
- **增强（Phase 2）**：blast radius —— 只在「常量/宏/全局/类型变更」这类会跨文件引爆的变更上，把评审范围从「变更行」扩展到「受影响函数」，避免 `#define BUF_SIZE 256` → `32` 这类全局性漏洞漏报。

---

## 3. 现状盘点（sgre 已有的增量相关能力）

| 能力 | 现状 | 位置 |
|---|---|---|
| 索引层增量 | 已有：按 checksum 跳过未变文件，重解析变化文件 | `indexer/indexer.go:93-101` |
| 语义图 | **无增量**：每次 scan 全量 `ClearGraph` + 重建 | `cli/scan.go:152-160` |
| 检测事件 | **无增量**：每次 `ClearSecurityEvents` + 全量重跑 | `cli/scan.go:221-231` |
| 收敛 planner | **无增量**：每次对所有类型全量 `Plan` | `cli/scan.go:248-278` |
| 候选行内信息 | 已有 `SourceLine`（flow 源头行） | `planner/evidence_package.go` |
| findings 幂等 | 已有：扫描内幂等 `uq_finding_loc(scan_id, rule_id, file_path, line_number, function_name)` | `db/schema.go:215` |
| baseline 过滤 | **已有雏形**：`--baseline <scan-id>` 按 `(file, line, rule)` 过滤 | `cli/suppression.go:64-103` |
| 目标范围裁剪 | 已有：`scopeToTarget` 按目录裁剪候选 | `cli/scan.go:638` |
| 输出隔离 | 已有：`scans/<scan_id>/` + `sc_` 前缀 | `report/protocol.go` |

**关键判断**：sgre 已经踩在增量检视的门槛上——`--baseline`、`scopeToTarget`、`SourceLine` 都是现成的积木。缺的是：

1. **git diff 层**（算变更文件 + 变更行）。
2. **跨扫描稳定的 finding 指纹**（现有 baseline 用 `file+line`，行号一漂移就失效）。
3. **稳定 review 锚点**（重复执行幂等）。
4. **命令面 + agent 编排 + 输出命名空间**。

---

## 4. 核心设计决策

### 4.1 三个正交的「增量」维度

| 维度 | 回答 | 决定 |
|---|---|---|
| 文件范围（file scope） | 哪些文件需要参与分析 | 引擎索引/建图范围（Phase 1 仍全量，Phase 2 可选裁剪） |
| 行范围（line scope） | finding 是否在本次 diff 内 | 候选是否进入 AI 评审 |
| 新问题（novelty） | 该问题是否已经报过 | 是否重复上报 |

三者正交、可独立开关。Phase 1 只做「行范围 + 新问题」，**不碰文件范围**（引擎照常全量跑），这是承重安全的关键。

### 4.2 稳定 review 锚点（重复执行的基石）

重复执行的最大障碍是：每次跑都生成新的随机 `scan_id`，无法幂等。

引入 `review_sessions` 表，`review_id` **由 (kind, base_sha, head_sha) 确定性生成**：

```sql
CREATE TABLE IF NOT EXISTS review_sessions (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    review_id     TEXT NOT NULL UNIQUE,     -- 确定性: pr_<base_short7>_<head_short7>
    kind          TEXT NOT NULL,            -- 'diff' | 'pr' | 'mr'
    base_ref      TEXT NOT NULL,            -- 基线: merge-base / HEAD~1 / 显式
    head_ref      TEXT NOT NULL,            -- HEAD
    base_sha      TEXT NOT NULL,
    head_sha      TEXT NOT NULL,
    changed_files TEXT,                     -- JSON: 变更文件 + hunks 变更行
    status        TEXT NOT NULL,            -- running | done | failed
    created_at    INTEGER,
    updated_at    INTEGER
);
```

- 同一 `(base, head)` 重复运行 → 命中同一 `review_id` → 幂等（复用现有 `UpsertFinding` 的 ON CONFLICT）。
- 新 commit → 新 head → 新 review，但 **base 不变** → 只对「相对 base 新增的变更行」产生新 finding。
- `review_id` 前缀 `pr_`/`mr_`/`diff_` 与全仓 `sc_` 前缀**天然隔离**，`report --audit`、`findings/`、SARIF 各走各的 scan_id 空间。

### 4.3 跨扫描稳定的 finding 指纹（去重关键）

现有 `uq_finding_loc` 的 `(file, line, rule)` 在**同一扫描内**幂等，但跨扫描行号漂移就失效。

新增（纯 additive，不破坏现有索引）：

```sql
ALTER TABLE findings ADD COLUMN fingerprint TEXT;
CREATE INDEX IF NOT EXISTS idx_findings_fingerprint ON findings(fingerprint);
```

```
fingerprint = sha256( rule_id + "\x00" + file_path + "\x00" + function_name
                      + "\x00" + sink_statement_hash )
```

- `sink_statement_hash` = finding 所在语句（或 ±1 行窗口）源码的哈希。
- 行号漂移不变 → 同一问题修了行号仍被识别为「已报过」。
- 代码被改（语句变了）→ 指纹变 → 视为「新问题」（合理：sink 处代码确实变了）。
- 跨扫描、跨 review、跨全仓 baseline 通用。

这是整个「重复执行」设计的基石：**去重不再依赖行号，而依赖内容**。

---

## 5. 端到端方案

### 5.1 命令面（CLI，向后兼容新增）

```
secguard diff [<base>]                 # 等价 git diff <base>..HEAD，默认 base=HEAD~1
secguard pr   [--base <branch>]        # base 自动 = git merge-base HEAD <main/master>
secguard mr   [--base <branch>]        # pr 别名（GitLab）
```

三个命令编译为同一个内部流程 `runDiffReviewCmd(kind, base, head)`，复用现有全局 `--db` / `--exclude` / `--context-lines` / `--fail-on`。

### 5.2 Git 层（新增 `internal/git` 包）

纯 `exec git`（二进制已跨平台；用户能跑 `git diff` 必有 git；`go.mod` 无 git 依赖，不引入重量级 go-git）：

```go
type Diff struct {
    Base, Head   string
    ChangedFiles []ChangedFile
}
type ChangedFile struct {
    Path    string   // 变更后路径
    Status  string   // A/M/D/R
    OldPath string   // rename 源
    Lines   []int    // 本次 diff 中「新增/修改」的行号集合（new 侧行号）
}
```

- `git merge-base HEAD <base>` → base_sha（`pr`/`mr` 自动探测 main/master）。
- `git diff -M -U0 <base>..HEAD -- '*.c' '*.h'` → 变更文件 + hunks。
- 解析 unified diff，产出每文件**变更行号集合**（added 行的 new 行号）。
- 非 git 目录 / git 不可用 → **报错退出，绝不降级成全仓**（否则会把「增量」误当「全量」，静默漏报）。

### 5.3 引擎编排（最小侵入，不动核心）

**原则：不改造 indexer/graph/planner 的核心逻辑，只在 CLI 编排层做「范围裁剪」。**

`runDiffReviewCmd` 内部：

1. git 层算出 `changedFiles` + 变更行集合。
2. **跑完整 pipeline**：复用现有「索引 → 建图 → 检测 → 收敛」链路（checksum 跳过未变文件；graph/events 照常 clear+rebuild）。**全量计算是安全正确性需要**——一个 NULL 源在行 10、解引用在行 500 的流，必须看到全文件才能判。
   - 实现：把 `cli/scan.go` 里「索引+建图+检测+plan」这一段**抽成可复用内部函数** `runPipeline(ctx, ...) → []planner.PlanResult`，不落 findings。这是**纯重构**，全仓 scan 与增量 review 调用同一函数，行为不变，用现有 contract 测试回归。
3. **候选裁剪（行范围 + 新问题）**：
   - `scopeToDiffLines(candidates, changedFiles)`：保留满足以下任一条件的候选：
     - **sink 行** ∈ 变更行集合（`EvidenceItem.Target.Line`）；
     - **flow 源头行** ∈ 变更行集合（`EvidenceItem.SourceLine`）—— 捕获「改了行 10 导致行 500 解引用」。
   - `filterByBaseline(candidates, baselineFingerprints)`：丢弃 fingerprint 已存在于「该 PR 历史 review + 全仓 baseline scan」的候选 → 只剩「新问题」。
4. **AI 分类 + 落 findings**：复用现有 `report --write-json` / `--review-json` / `--audit`，但 scan_id 用稳定 `review_id`，从而幂等。
5. **输出**：写到独立命名空间 `.codeagent/secguard-clang/reviews/<review_id>/`，**绝不写 `scans/`**。

### 5.4 Agent 编排层（extension，复用为主）

- 新增三个 slash command（thin wrapper，`{{include shared/...}}`）：`/secguard diff`、`/secguard pr`、`/secguard mr`。
- 新增 `shared/pr-review-instructions.md`（或在 command-instructions 里加一个增量 section）：解析 base → 调 `secguard pr` → 拿到 review_id + 候选 → 复用 `security-auditor` 子代理分类 → `--audit` 出报告。
- **20 个 skills + security-auditor 子代理零改动**：候选形态（`candidates/<type>/_index.md`、`Evidence` 文件）与全仓完全一致，只是候选集是裁剪后的子集。**AI 层完全不需要知道「这是增量」**——这是设计的核心简化点。
- 最终回复沿用现有 Output Format，报告头标注「本次为增量检视，base=<..> head=<..>」。

### 5.5 输出契约（隔离，承重保障）

```
.codeagent/secguard-clang/
├── scans/<scan_id>/        # 全仓扫描（现状，不动）
├── reviews/<review_id>/    # 增量检视（新，独立命名空间）
│   ├── diff.json           # 本次 base/head/变更文件/变更行，可审计
│   ├── report.md
│   ├── candidates/ …
│   ├── findings/ …
│   └── result.sarif
└── .sgre/sgre.db           # 共享 DB（findings 带 review_id，不污染 scans 的 scan_id 空间）
```

**隔离保证**：

- `review_id` 前缀（`pr_`/`mr_`/`diff_`）与 `sc_` 不冲突 → 所有按 `scan_id` 分区的逻辑天然分离。
- 全仓 `scan` 命令路径**零行为改动**（仅一处纯重构抽 `runPipeline`）。
- 增量检视**不会**更新 `scans/latest` 软链（那是全仓扫描的语义），避免破坏「latest 指向最近一次全仓」的既有契约。

---

## 6. 重复执行场景专门设计（重点）

### 6.1 同 PR 反复 push（CI 每次 push 都跑）

- base 固定（merge-base），head 每次更新 → `review_id` 每次不同。
- 但 **fingerprint 去重**：第二次 push 只报「相对 base 新增/改动行上、指纹未见过」的问题。
- 实现：**基线 fingerprint 集合 = 该 PR 所有历史 review 的 findings ∪ 全仓 baseline scan 的 findings**。已报过的问题（同 fingerprint）被过滤。

### 6.2 本地反复手动跑 `/secguard pr`（同一 head）

- `review_id = f(base, head)` 相同 → 命中同一 `review_sessions` 行 → 幂等 upsert。
- 结果不漂移、不重复（`UpsertFinding` 的 ON CONFLICT 直接复用）。

### 6.3 修了又提交（已修复问题不应再出现）

- 修复 = sink 语句变化 → fingerprint 变。若修复后该行仍在 diff 内 → 作为「新问题」出现一次（合理）；若修复移出了 diff 行 → `scopeToDiffLines` 直接裁掉。
- 已 dismiss 的 finding：现有 `suppressionIndex`（`file+line+rule`）跨 scan 生效（dismissed 存的是 file_path+line+rule，天然跨 review），继续抑制。

### 6.4 幂等与并发补充

- `review_sessions` upsert 用 `INSERT ... ON CONFLICT(review_id) DO UPDATE`；配合 SQLite WAL，支持 CI 并发跑同一 review（最后写入者收敛，findings 幂等）。
- 增量「基线」不存在时（首次跑 / 无历史 review / 无全仓 scan）：降级为「全量变更行 + 无去重」，并在报告头显式说明「无基线，本次为首次增量检视」。

---

## 7. 分阶段落地（风险控制）

### Phase 1（安全、可立即上）：行范围裁剪 + 指纹去重 ✅ 已实现

新增：`internal/git`（git diff 解析 + 单测）、`cli/diff.go`（`runDiffReviewCmd`）、`cli/fingerprint.go`、`cli/pipeline.go`、`review_sessions` 表、`findings.fingerprint` 列、三个 slash command + 增量 instructions。

改动：`scan.go` 抽 `runPipeline`（纯重构）；`report.go` 的 `--write`/`--write-json` 自动算 fingerprint（additive）；`autoConfirmFindings` 补 fingerprint（additive）。

复用：agent 编排 + 20 skills + security-auditor（零改动）。

承重影响：仅 schema 加列 + 抽函数，全仓 scan 回归测试覆盖（`go test ./...` 与 `-tags nosqlite` 均绿）。

重复执行：6.1 / 6.2 / 6.3 / 6.4 全覆盖（已冒烟验证：同一 head 幂等、全仓基线去重存量 null-deref）。

> 实现差异说明：指纹用「rule_id + file + function + sink 语句文本（trim 后整行）」计算，比设计稿的 `sink_statement_hash` 更具体；注释改动会使该行进入 diff 并被报告一次（无基线时），这是已知的「变更行粒度」边界，靠 dismiss 抑制兜底。

### Phase 2（可选优化，默认关闭）：blast-radius 扩展 + 增量引擎

- **blast radius 扩展评审范围**：检测到常量/宏/全局/类型变更时，用 `GLOBAL_ACCESS` / `CALL` 边反向找受影响函数（`ReachableFromEntries`），纳入评审范围，应对 `BUF_SIZE` 类全局性漏洞。
- **增量建图/检测**：按「变更函数」为入口做局部建图 + 局部检测（借鉴 code-review-graph 的 SHA-256 增量），flag `--incremental-engine` 默认关。
- 承重影响：都在增量命令内部，全仓 `scan` 不受影响。

---

## 8. 承重功能保障（全文最重要的一条）

全仓扫描是承重功能，设计上通过「四个不变」保证安全：

1. **引擎核心不变**：indexer / graph / evidence / planner 的算法与数据模型零改动（Phase 1 只抽函数 + 加列）。
2. **全仓命令路径不变**：`secguard scan` / `index` / `plan` / `report` 的参数与输出契约完全不变。
3. **输出命名空间物理隔离**：增量写 `reviews/`，全仓写 `scans/`，互不触碰；增量不更新 `scans/latest`。
4. **回归门禁**：新增功能合入前，必须通过现有全仓 `go test ./...`（含 `contract_test.go`、`scan_test.go`、`report_audit_test.go`），任何全仓行为回归一律视为阻塞。

---

## 9. 风险与对策

| 风险 | 对策 |
|---|---|
| 改动引擎破坏全仓 | Phase 1 不碰引擎核心；纯重构 + 加列；全仓回归必须绿 |
| 行号漂移导致去重失效 | fingerprint 用内容哈希，不用行号 |
| flow 漏洞漏报（改行 10 影响行 500） | 裁剪时同时看 `Target.Line`（sink）与 `SourceLine`（源头） |
| 常量/宏变更跨文件引爆漏报 | Phase 2 blast-radius（GLOBAL_ACCESS 边） |
| CI 并发写同 review | review_sessions upsert + findings 幂等 upsert + WAL |
| git 不可用 / 非 git 目录 | 报错退出，绝不 fallback 全仓（防「增量误当全量」漏报） |
| baseline 缺失 | 降级为「全量变更行 + 无去重」并在报告头显式标注 |

---

## 10. 待确认决策（实现前需拍板）

1. **基线来源**：PR 首次跑时，基线用「全仓最近一次 scan 的 findings」还是「在 merge-base 现场重扫一次」？（前者快、可能有 stale；后者准、慢。推荐：优先用现有全仓 scan findings，缺失时显式提示。）
2. **变更行判定粒度**：`diff`/`pr` 是否默认含 `.h` 头文件？（头文件宏/类型变更常引爆多文件，建议默认含。）
3. **blast radius** 是否纳入 Phase 1，还是严格放 Phase 2？（推荐放 Phase 2，先用最小可用闭环验证价值。）
