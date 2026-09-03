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

export default tool({
  description:
    "Read SecGuard scan-level performance and convergence metrics from the local database: per-phase durations (index/graph/detectors/plan/report), raw->converged candidate reduction, report + evidence size, and an estimated AI-input token count (bytes ÷ 4). With all=true, lists the most recent runs newest-first. Read-only — it never writes or re-scans. Use it to answer 'how long did the scan take' or 'how much context/cost did this scan consume'.",
  args: {
    all: tool.schema
      .boolean()
      .optional()
      .describe("List recent runs (newest first) instead of just the latest scan."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = path.join(workDir, ".codeagent", "secguard-clang", ".sgre", "sgre.db")

    try {
      const cmd = args.all
        ? Bun.$`${secguardBin} metrics --all --db ${dbPath}`
        : Bun.$`${secguardBin} metrics --db ${dbPath}`
      const result = await cmd.cwd(workDir).quiet().text()
      return result.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify(
        {
          error: err,
          message:
            "No scan metrics found or secguard is unavailable. Run secguard_scan first to record metrics.",
          db_path: dbPath,
        },
        null,
        2,
      )
    }
  },
})
