import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import { fileURLToPath } from "url"

function findSecguard(context: { worktree?: string, directory?: string }): string {
  // Market 安装：优先用插件自带 bin/ 里按 os/arch 选型的二进制（不依赖 PATH）
  const pluginDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
  const os = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux"
  const arch = process.arch === "x64" ? "amd64" : process.arch
  const bundled = path.join(pluginDir, "bin", `secguard-${os}-${arch}${os === "windows" ? ".exe" : ""}`)
  if (fs.existsSync(bundled)) return bundled
  // 项目级 .opencode/bin/secguard（旧约定）
  for (const dir of [context.directory, context.worktree, "."]) {
    if (!dir || dir === "/") continue
    const local = path.join(dir, ".opencode/bin/secguard")
    if (fs.existsSync(local)) return local
  }
  // 非 Market 安装：PATH 上的 secguard
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
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = path.join(workDir, ".codeagent", "secguard-clang", ".sgre", "sgre.db")

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