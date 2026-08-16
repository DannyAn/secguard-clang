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
    "Check SecGuard index status: whether sgre.db exists, when it was last updated, how many files/functions are indexed, and whether the index is stale (source files changed since last index).",
  args: {},
  async execute(_args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = path.join(workDir, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")

    try {
      const result = await Bun.$`${secguardBin} status --db ${dbPath}`
        .cwd(workDir)
        .quiet()
        .text()
      return result.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify(
        {
          indexed: false,
          error: err,
          message: "No sgre.db found or secguard not available. Run secguard_scan to create an index.",
          db_path: dbPath,
        },
        null,
        2
      )
    }
  },
})
