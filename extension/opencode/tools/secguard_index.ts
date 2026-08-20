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
    "Index a C codebase into the SecGuard SQLite database (sgre.db). Parses all .c/.h files with tree-sitter, extracts functions, builds call graph and data flow graph, runs all security event detectors.",
  args: {
    path: tool.schema
      .string()
      .optional()
      .describe("Target path to index. Defaults to current workspace root."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const targetPath = args.path || workDir
    const sgreDir = path.join(workDir, ".codeagent", "secguard-clang", ".sgre")
    if (!fs.existsSync(sgreDir)) fs.mkdirSync(sgreDir, { recursive: true })
    const dbPath = path.join(sgreDir, "sgre.db")

    try {
      const result = await Bun.$`${secguardBin} index --db ${dbPath} ${targetPath}`
        .cwd(workDir)
        .quiet()
        .text()

      return result.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: err, db_path: dbPath, target: targetPath }, null, 2)
    }
  },
})
