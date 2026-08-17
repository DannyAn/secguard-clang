import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"

function findSecguard(context: { worktree?: string, directory?: string }): string {
  for (const dir of [context.directory, context.worktree, "."]) {
    if (!dir || dir === "/") continue
    const bundled = path.join(dir, ".opencode/bin/secguard")
    if (fs.existsSync(bundled)) return bundled
  }
  return "secguard"
}

function printPlanSummary(w: { write(s: string): boolean }, goJson: any): void {
  const vulnType = goJson?.vulnerability_type ?? "N/A"
  const cwe = goJson?.cwe ?? "CWE-Other"
  const seedCount = goJson?.summary?.seed_count ?? 0
  const finalCount = goJson?.summary?.final_count ?? 0
  const dedupedCount = goJson?.summary?.deduped_count ?? 0
  const filters = goJson?.summary?.filters ?? []
  const candidates = goJson?.candidates ?? []

  let out = "## SecGuard Plan Summary\n\n"
  out += "| Field | Value |\n"
  out += "|-------|-------|\n"
  out += `| Vulnerability Type | ${vulnType} |\n`
  out += `| CWE | ${cwe} |\n`
  out += `| Seed Count | ${seedCount} |\n`
  out += `| Final Count | ${finalCount} |\n`
  out += `| Deduped Count | ${dedupedCount} |\n\n`

  if (filters.length > 0) {
    out += "### Filter Chain\n\n"
    out += "| Filter | Input | Output |\n"
    out += "|--------|-------|--------|\n"
    for (const f of filters) {
      out += `| ${f?.name ?? "?"} | ${f?.input_count ?? 0} | ${f?.output_count ?? 0} |\n`
    }
    out += "\n"
  }

  out += "### Candidates\n\n"
  if (candidates.length === 0) {
    out += "No candidates after convergence.\n"
  } else {
    out += "| # | Function | File:Line | Variable | Suspicion |\n"
    out += "|---|----------|-----------|----------|-----------|\n"
    for (let i = 0; i < candidates.length; i++) {
      const c = candidates[i]
      const fn = c?.target?.function ?? "?"
      const file = c?.target?.file ?? "?"
      const line = c?.target?.line ?? 0
      const variable = c?.target?.variable ?? ""
      const suspicion = c?.suspicion_level ?? ""
      out += `| ${i + 1} | ${fn} | ${file}:${line} | ${variable} | ${suspicion} |\n`
    }
  }

  w.write(out)
}

export default tool({
  description:
    "Run the SecGuard convergence pipeline for ONE vulnerability type. Returns ALL deduped, risk-ranked evidence candidates (no cap) as JSON. Call `secguard types` first to discover the valid type names — this tool passes the type through to the binary, which rejects unknown names with its own authoritative list.",
  args: {
    vuln_type: tool.schema
      .string()
      .describe(
        "Kebab-case vulnerability type name. Get the current list from `secguard types` (e.g. null-deref, buffer-overflow, out-of-bounds, integer-overflow)."
      ),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = path.join(workDir, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")

    try {
      const cmd = Bun.$`${secguardBin} plan --db ${dbPath} ${args.vuln_type}`
      const result = await cmd.cwd(workDir).quiet().text()

      try {
        const goJson = JSON.parse(result.trim())
        printPlanSummary(process.stderr, goJson)

        const vulnType = goJson?.vulnerability_type ?? args.vuln_type
        const cwe = goJson?.cwe ?? ""
        const dedupedCount = goJson?.deduped_count ?? goJson?.candidate_count ?? 0
        const candidatesFile = goJson?.candidates_file ?? ""

        // 从 candidates_file 读取完整 candidates（plan 命令现在把完整数据写文件，
        // stdout 只有摘要）。如果文件读取失败，返回摘要让 agent 回退到 report.md。
        let compactCandidates: any[] = []
        if (candidatesFile && fs.existsSync(candidatesFile)) {
          const fileContent = fs.readFileSync(candidatesFile, "utf-8")
          const fullJson = JSON.parse(fileContent.trim())
          const candidates = fullJson?.candidates ?? []
          compactCandidates = candidates.map((c: any, i: number) => ({
            n: i + 1,
            fn: c?.target?.function ?? "?",
            file: c?.target?.file ?? "?",
            line: c?.target?.line ?? 0,
            variable: c?.target?.variable ?? "",
            suspicion: c?.suspicion_level ?? "",
          }))
        }

        return JSON.stringify({
          vulnerability_type: vulnType,
          cwe: cwe,
          deduped_count: dedupedCount,
          candidates: compactCandidates,
        }, null, 2)
      } catch {
        // 不返回原始 result（候选多时可能触发 OpenCode 截断）。返回精简错误，
        // agent 可从 report.md 获取该类型的候选列表。
        return JSON.stringify({ error: "Plan output unparseable; read report.md for this type's candidates.", vuln_type: args.vuln_type, db_path: dbPath }, null, 2)
      }
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: err, vuln_type: args.vuln_type, db_path: dbPath }, null, 2)
    }
  },
})
