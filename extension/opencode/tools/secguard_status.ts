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
    "Check SecGuard index status, per-type classification progress for a scan, or settled subagent reports (reports=true), and atomically claim a dispatch batch before spawning a worker (claim_type/claim_range/claim_holder). By default returns the index summary (whether sgre.db exists, last updated, files/functions indexed, staleness). show_limits=true returns the engine/host concurrency caps and AI-stage budgets instead — read host_max_concurrency there rather than probing the host by hitting a spawn error. When per_type is true, returns the per-vulnerability-type progress array (candidate_count / written_count / terminal_state / already_covered_ranges / in_flight_ranges) for the scan identified by scan_id (defaults to the latest scan) — this is the DB-authoritative verification the orchestrator uses to judge success/partial/failed per type, so prefer it over any subagent self-report. When claim_type is set, atomically reserves that type+range: spawn the batch ONLY when the result has claimed=true; claimed=false means another worker holds it (reason held) or it is already settled (reason done — pass reclaim only for a deliberate needs_context re-review).",
  args: {
    per_type: tool.schema
      .boolean()
      .optional()
      .describe("When true, return per-type candidate/written/terminal_state for a scan instead of the index summary."),
    reports: tool.schema
      .boolean()
      .optional()
      .describe("When true, list settled subagent reports from .sgre/.tmp/*-report*.json (subagent_id / scan_id / processed_types / failed_types / needs_context / valid) plus heartbeat_age_ms / stalled / progress (classified vs total). Use this after an Agent-call timeout to decide whether a batch already finished before re-dispatching, and to tell a live-but-slow worker from a dead one."),
    show_limits: tool.schema
      .boolean()
      .optional()
      .describe("When true, return the engine concurrency caps, the AI host concurrency cap and the AI-stage budgets instead of index status. Read host_max_concurrency here instead of probing the host's spawn limit."),
    claim_type: tool.schema
      .string()
      .optional()
      .describe("Vulnerability type to atomically reserve before dispatching its batch (requires claim_range and claim_holder). Spawn only when the result says claimed=true."),
    claim_range: tool.schema
      .string()
      .optional()
      .describe("Candidate range of the batch being reserved (required; use \"all\" for the whole type)."),
    claim_holder: tool.schema
      .string()
      .optional()
      .describe("Unique holder token for this dispatch (e.g. batch-<type>-<range>-<epoch-ms>); not necessarily the host's subagent id."),
    reclaim: tool.schema
      .boolean()
      .optional()
      .describe("With claim_type: take over a done/held range for a deliberate re-review (e.g. needs_context). Never use it to recover from a missing report."),
    scan_id: tool.schema
      .string()
      .optional()
      .describe("Scan ID to query per-type status for. Defaults to the latest scan when omitted."),
    db_path: tool.schema
      .string()
      .optional()
      .describe("Path to sgre.db; omit for <workdir>/.codeagent/secguard-clang/.sgre/sgre.db."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = args.db_path || path.join(workDir, ".codeagent", "secguard-clang", ".sgre", "sgre.db")

    try {
      let result: string
      if (args.claim_type) {
        if (!args.claim_range || !args.claim_holder) {
          return JSON.stringify({ claimed: false, error: "claim_type requires claim_range and claim_holder" })
        }
        const cmd = [
          secguardBin, "status", "--db", dbPath,
          "--claim-type", args.claim_type,
          "--claim-range", args.claim_range,
          "--claim-holder", args.claim_holder,
        ]
        if (args.reclaim) cmd.push("--reclaim")
        if (args.scan_id) cmd.push("--scan-id", args.scan_id)
        result = await Bun.$`${cmd}`.cwd(workDir).quiet().text()
      } else if (args.show_limits) {
        result = await Bun.$`${secguardBin} status --db ${dbPath} --show-limits`.cwd(workDir).quiet().text()
      } else if (args.reports) {
        const scanId = args.scan_id || ""
        if (scanId) {
          result = await Bun.$`${secguardBin} status --db ${dbPath} --reports --scan-id=${scanId}`
            .cwd(workDir)
            .quiet()
            .text()
        } else {
          result = await Bun.$`${secguardBin} status --db ${dbPath} --reports`
            .cwd(workDir)
            .quiet()
            .text()
        }
      } else if (args.per_type) {
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
