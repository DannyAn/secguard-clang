import { tool } from "@opencode-ai/plugin"
import path from "path"
import { findSecguard } from "../findSecguard"


// withKill bounds the subprocess and TERMINATES it on expiry so a slow recovery
// cannot hang past the host budget. finalize is idempotent (re-running it only
// re-upserts the same verdicts and re-renders the same artifacts), so a timeout
// reads outcome_unknown and the caller re-runs it — never a blind rescan.
async function withKill(proc: { text(): Promise<string>, kill(): void }, ms: number, label: string): Promise<string> {
  const timer = setTimeout(() => { try { proc.kill() } catch { /* already exited */ } }, ms)
  try {
    return await proc.text()
  } catch (e: any) {
    throw new Error(`${label} outcome_unknown after ${ms}ms (subprocess killed; finalize is idempotent — re-run it, never rescan): ${e?.message || e}`)
  } finally {
    clearTimeout(timer)
  }
}

export default tool({
  description:
    "One-shot recovery that finishes an interrupted scan from data already on disk: it replays every staged verdict array under .sgre/.tmp/ (the JSON the subagents wrote but the orchestrator never absorbed), marks each type complete, re-runs the terminal audit, and regenerates result.sarif / report.md / findings/. Use it after a host failure (subagent spawn failure, timeout, or an interrupted session) left staged verdicts unpersisted — NOT as a normal scan step (a healthy run's single writer is `secguard report --audit`). Idempotent: re-running re-upserts the same verdicts and re-renders the same artifacts. Returns scan_id, replayed (files / findings_written / dismissed_written / failed_files), completed_types, incomplete_types, result_sarif (exists/bytes), findings_count, and status ok|partial|failed (failed = result.sarif was not produced; partial = some types still have unclassified candidates). Orchestrator-only: a security-auditor subagent must never call it.",
  args: {
    scan_id: tool.schema
      .string()
      .optional()
      .describe("Scan ID to finalize. Defaults to the latest scan when omitted."),
    output_dir: tool.schema
      .string()
      .optional()
      .describe("Scan output directory. Defaults to the canonical .codeagent/secguard-clang/scans/<scan_id>/ derived from the DB path; pass it only when the interrupted scan wrote artifacts elsewhere."),
    allow_partial: tool.schema
      .boolean()
      .optional()
      .describe("Emit explicitly PARTIAL-labelled artifacts when some types still have unclassified candidates, instead of leaving them unrendered. Only set it when you accept a partial verdict set."),
    db_path: tool.schema
      .string()
      .optional()
      .describe("Absolute path to sgre.db. Omit for <workdir>/.codeagent/secguard-clang/.sgre/sgre.db."),
    timeout_ms: tool.schema
      .number()
      .optional()
      .describe("Wall-clock budget in milliseconds (default 300000 = 5 min). On expiry the subprocess is KILLED; finalize is idempotent, so re-run it — never rescan."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = args.db_path || path.join(workDir, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
    const timeoutMs = args.timeout_ms && args.timeout_ms > 0 ? Math.floor(args.timeout_ms) : 300_000

    try {
      const cmd = [secguardBin, "finalize", "--db", dbPath]
      if (args.scan_id) cmd.push("--scan-id", args.scan_id)
      if (args.output_dir) cmd.push("--output-dir", args.output_dir)
      if (args.allow_partial) cmd.push("--allow-partial")
      const result = await withKill(Bun.$`${cmd}`.cwd(workDir).quiet(), timeoutMs, "secguard finalize")
      return result.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      const notFound = /no sgre\.db|no database|not found|run 'secguard scan'/i.test(err)
      return JSON.stringify(
        {
          status: "error",
          error: err,
          db_path: dbPath,
          message: notFound
            ? "No sgre.db found — run secguard_scan first, then finalize."
            : "finalize failed; it is idempotent, so re-run it after checking the error (never rescan).",
        },
        null,
        2,
      )
    }
  },
})
