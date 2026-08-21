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
    "List the vulnerability types SecGuard detects, each with its name and CWE. This is the authoritative runtime list — call it first to discover/validate type names before scanning or loading skills; never hardcode type names or counts.",
  args: {},
  async execute(_args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)

    try {
      const result = await Bun.$`${secguardBin} types`.cwd(workDir).quiet().text()
      return result.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: err }, null, 2)
    }
  },
})
