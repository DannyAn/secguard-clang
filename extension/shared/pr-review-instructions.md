Review only the incremental changes of a PR/MR (or an arbitrary git diff) with the SecGuard pipeline, instead of re-scanning the whole repo and re-surfacing every pre-existing finding.

## 入口（三个命令，同一引擎）

- `/secguard diff [<base>]` — review `base..HEAD`（base 缺省 `HEAD~1`）
- `/secguard pr [--base <branch>]` — review `merge-base..HEAD`（base 缺省 `git merge-base HEAD origin/main|origin/master|main|master`）
- `/secguard mr [--base <branch>]` — pr 的 GitLab 别名

`secguard diff|pr|mr` 内部做四件事：① 用 git 算出变更文件 + 变更行；② 跑完整分析管线（索引→建图→检测→收敛）；③ 只保留「sink 行或 flow 源头行落在变更行上、且内容指纹未在基线（全仓历史 findings + 既往 review）出现」的候选；④ 写 `.codeagent/secguard-clang/reviews/<review_id>/`。它**绝不**碰全仓 `scans/`，也**绝不**更新 `scans/latest`。

## 工作流（复用全仓的 security-auditor 与 20 个 skills，零改动）

1. 调 `secguard pr`（或 `diff`/`mr`），拿到 `review_id` + `review_dir` + `candidates_by_type` + `total_candidates`。输出结构与全仓 `scan` 同构：**`review_id` 就是后续写入要用的 `scan_id`**，`review_dir` 就是 `--output-dir`。
2. 对每个 `candidates_by_type > 0` 的类型：读 `<review_dir>/candidates/<type>/_index.md`（`Source` 列即 file:line 原始语句，`Hint` 列即管线预计算判定事实，`Evidence` 列即候选证据文件精确名），按全仓同样的分类规则判定 confirmed / dismissed（二元）；只写 confirmed findings，dismissed 不写不落库不计数。
   - confirmed → 从 `_index.md` 的 `Source` 列直接判定。
   - suspected/possible → 先按 `Source`+`Hint` 判定（`Hint`：`src@N`=空指针来源行、`certain-null`/`maybe-null`=空指针确定性（非 null-deref 类型）、`null@cfg-proof`/`null@malloc-fail`/`null@caller-arg`/`null@callback-entry`/`null@external-unknown`=null-deref 来源档位（`null@callback-entry`=函数指针注册的 callback，参数可空性由注册处上下文决定）、`tainted`=污点来源、`weak-guard`=弱守卫、`reason@<text>`=crypto 检测器判定理由、`key-size@N`=声明密钥字节数（<16 低于现代密码下限）、`buf@<name>`/`cap@N`/`idx@<expr>`=BO/OOB 的缓冲区/容量/索引（常量越过 cap@ 是机器证明，变量需判范围）、`alloc@N`/`acquire@N`/`leak@definite`/`leak@conditional`/`escape@none|store|return`/`free@N,M`=leak 的分配行/确定性/释放通道状态/被绕过的释放行、`range@<interval>`=除数已证区间、`callers@<census>`=除法调用点普查、`origin@<kind>`=未初始化存储类型、`decl@N`=未初始化声明行、`expected@<type>`/`actual@<type>`/`cast@<type>`=参数类型期望/实际/显式转换、`fmt-arg@<expr>`=格式化参数、`path-arg@<expr>`=路径参数（遍历根）、`value-shape@<masked>`=硬编码字面量掩码形状、`async-unsafe@<fn>`=handler 调用的非异步安全函数、`subject@<name>`/`count-field@<field>`/`evidence-kind@<kind>`=隐式契约主体/门控字段/证据来源、`cond@<callee>`=double-free 条件释放助手）；Hint 不足时才按 `Evidence` 列原样打开 `NNN_<file>_<line>.md`，读内嵌 `## Code Context`。没看全的候选标 `suspected`，绝不 dismissed。
   - 源码已内嵌，**禁止逐候选发 source READ**。
3. 落库（幂等，重复跑 upsert 不重复）：仅含 confirmed 逐条数组，dismissed 不写入。
   `secguard report --write-json <tmpdir>/<type>.json --scan-id <review_id> --db <db_path>`
   `<db_path>` = `<review_dir>/../../.sgre/sgre.db`，`<tmpdir>` = `<review_dir>/../../.sgre/.tmp/`（与全仓同一套路径派生）。
   每个类型写完 confirmed findings 后调 `secguard report --complete-type <type> --scan-id <review_id> --db <db_path>` 标记 ai_stage_status='done'。
4. 所有类型写完（含 --complete-type）跑一次：
   `secguard report --audit --scan-id <review_id> --output-dir <review_dir> --ai-duration-ms <ms>`
   再读 `<review_dir>/result.sarif` 确认非空、`ls <review_dir>/findings/` 确认判定落盘。`<ms>` 是本轮 AI 研判实测墙钟（从拿到 review 结果进入分类，到本次收尾 audit 的毫秒数）。
    审计前无需复核 auto-confirmed：它们是机器判定的确定性发现（scan 阶段已标记 `review_status='confirmed'`），无二次复核环节；`secguard report --list-auto-confirmed --scan-id <review_id> --db <db_path>` 恒返回 `count: 0`。

## 与全仓 scan 的关键区别（agent 只需记住这些）

- 候选**已经**是「变更行上的新问题」，数量通常远小于全仓。不要因为候选少就跳过某类型；也不要重复跑 `secguard scan`/`plan`（管线已跑完）。
- `review_id` 前缀 `diff_`/`pr_`/`mr_`（全仓是 `sc_`）；`review_dir` 在 `reviews/`（全仓在 `scans/`）。DB 是同一个 `.codeagent/secguard-clang/.sgre/sgre.db`。
- 重复跑同一 base/head 是幂等的；新 commit 会生成新 review 但 base 不变，已报过的问题靠指纹去重不再重复出现。
- 分类规则、技能命名空间、输出格式与全仓完全一致（见 `/secguard` 的 Classification Rules 与 Output Format）。最终回复的报告头改为：`代码仓：<abs path>；检视范围：<base>..<head>（变更文件 N 个）`。

## 边界

- 非 git 仓库 / git 不可用时，`secguard pr` 会直接报错退出——不要降级成全仓 scan（那会误把增量当全量）。
- 无基线（首次跑、无历史全仓 findings）时，去重自动失效，报告头应注明「首次增量检视，无基线」。
