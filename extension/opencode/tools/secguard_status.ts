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
    "Check SecGuard index status, or per-type classification progress for a scan. By default returns the index summary (whether sgre.db exists, last updated, files/functions indexed, staleness). When per_type is true, returns the per-vulnerability-type progress array (candidate_count / written_count / terminal_state) for the scan identified by scan_id (defaults to the latest scan) — this is the DB-authoritative verification the orchestrator uses to judge success/partial/failed per type, so prefer it over any subagent self-report.",
  args: {
    per_type: tool.schema
      .boolean()
      .optional()
      .describe("When true, return per-type candidate/written/terminal_state for a scan instead of the index summary."),
    scan_id: tool.schema
      .string()
      .optional()
      .describe("Scan ID to query per-type status for. Defaults to the latest scan when omitted."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = path.join(workDir, ".codeagent", "secguard-clang", ".sgre", "sgre.db")

    try {
      let result: string
      if (args.per_type) {
        const scanId = args.scan_id || ""
        if (scanId) {
          result = await Bun.$`${secguardBin} status --db ${dbPath} --per-type --scan-id=${scanId}`
            .cwd(workDir)
            .quiet()
            .text()
        } else {
          result = await Bun.$`${secguardBin} status --db ${dbPath} --per-type`
            .cwd(workDir)
            .quiet()
            .text()
        }
      } else {
        result = await Bun.$`${secguardBin} status --db ${dbPath}`
          .cwd(workDir)
          .quiet()
          .text()
      }
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
