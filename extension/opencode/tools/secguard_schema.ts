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
    "Discover the SecGuard database schema (column names and types for agent-queryable tables). Call this BEFORE secguard_db if you are unsure of column names — never guess. Tables: findings, scan_stats, files, functions, security_events. Pass a table name for one table's schema, or omit for all tables plus example queries.",
  args: {
    table: tool.schema
      .string()
      .optional()
      .describe("Optional table name to get schema for one table (e.g. 'findings'). Omit for all tables."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)

    try {
      const cmd = args.table
        ? Bun.$`${secguardBin} schema ${args.table}`
        : Bun.$`${secguardBin} schema`
      const result = await cmd.cwd(workDir).quiet().text()
      return result.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: err }, null, 2)
    }
  },
})