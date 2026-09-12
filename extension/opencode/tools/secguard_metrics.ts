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
    "Read SecGuard scan-level performance and convergence metrics from the local database: per-phase durations (index/graph/detectors/convergence/report), raw->converged candidate reduction, report + evidence size, and an estimated AI-input token count (bytes ÷ 4). duration_ms/duration_sec is the AUTOMATED-ANALYSIS wall clock only (index+graph+detectors+convergence+auto-confirm) and EXCLUDES the AI Agent classification stage, so never present it as end-to-end scan time. With all=true, lists the most recent runs newest-first. Read-only — it never writes or re-scans. Use it to answer 'how long did the automated analysis take' or 'how much context/cost did this scan consume'.",
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
