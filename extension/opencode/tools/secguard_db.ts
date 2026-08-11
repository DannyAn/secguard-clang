import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"

function findSecguard(context: { worktree?: string, directory?: string }): string {
  let dir = context.worktree || context.directory || "."
  if (dir === "/") dir = "."
  const bundled = path.join(dir, ".opencode/bin/secguard")
  if (fs.existsSync(bundled)) return bundled
  return "secguard"
}

export default tool({
  description:
    "Execute a read-only SQL query on the SecGuard database (sgre.db) and return results as JSON. SELECT queries only — INSERT/UPDATE/DELETE are rejected. Queries referencing the 'security_events' table are rejected (raw candidates are not exposed to agents — use secguard_scan/secguard_plan for converged evidence). Use secguard_report tool to write findings. Useful for inspecting findings, files, functions tables.",
  args: {
    sql: tool.schema
      .string()
      .describe("SELECT query to execute (read-only)"),
  },
  async execute(args, context) {
    let workDir = context.worktree || context.directory || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = path.join(workDir, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")

    const sqlUpper = args.sql.trim().toUpperCase()
    if (!sqlUpper.startsWith("SELECT") && !sqlUpper.startsWith("WITH")) {
      return JSON.stringify({ error: "Only SELECT queries are allowed. Use secguard_report tool to write findings." }, null, 2)
    }

    if (/\bsecurity_events\b/i.test(args.sql)) {
      return JSON.stringify({ error: "Querying the 'security_events' table is prohibited. This table contains raw pre-convergence candidates. Use secguard_scan or secguard_plan to obtain converged evidence packages. Use secguard_report to read/write findings." }, null, 2)
    }

    try {
      const result = await Bun.$`${secguardBin} db --db ${dbPath} ${args.sql}`
        .cwd(workDir)
        .quiet()
        .text()

      return result.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: err, db_path: dbPath }, null, 2)
    }
  },
})