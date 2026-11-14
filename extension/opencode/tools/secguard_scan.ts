import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import { findSecguard } from "../findSecguard"


function printScanSummary(
  w: { write(s: string): boolean },
  goJson: any,
  targetPath: string,
  workspace: string,
): void {
  const scanId = goJson?.scan_id ?? "N/A"
  const scanDir = goJson?.scan_dir ?? "N/A"
  const totalCandidates = goJson?.total_candidates ?? 0
  const filesIndexed = goJson?.index_summary?.files_indexed ?? "N/A"
  const functionsIndexed = goJson?.index_summary?.functions_indexed ?? "N/A"
  const linesOfCode = goJson?.index_summary?.lines_of_code ?? 0
  const autoConfirmed = goJson?.auto_confirmed_count ?? 0
  const candidatesByType: Record<string, number> = goJson?.candidates_by_type ?? {}
  const autoConfirmedByType: Record<string, number> = goJson?.auto_confirmed_by_type ?? {}

  // One scale line up front, mirroring report.md's `## Scan Overview`: the
  // console and the artifact must answer "how big was this scan" identically.
  const scaleParts = [
    typeof filesIndexed === "number" ? `${filesIndexed} files` : "files n/a",
    typeof functionsIndexed === "number" ? `${functionsIndexed} functions` : "functions n/a",
  ]
  if (typeof linesOfCode === "number" && linesOfCode > 0) scaleParts.push(`${linesOfCode} lines`)

  let out = "## SecGuard Scan Summary\n\n"
  out += `**此轮扫描规模：${scaleParts.join(" / ")}；收敛候选 ${totalCandidates} 个`
  if (autoConfirmed > 0) {
    out += `（其中 ${autoConfirmed} 个已由流水线自动确认）`
  }
  out += "。**\n\n"
  out += "| Field | Value |\n"
  out += "|-------|-------|\n"
  out += `| Scan ID | ${scanId} |\n`
  out += `| Target | ${targetPath} |\n`
  out += `| Workspace | ${workspace} |\n`
  out += `| Scan Dir | ${scanDir} |\n`
  out += `| Total Candidates | ${totalCandidates} |\n`
  out += `| Auto-confirmed (pipeline-proved) | ${autoConfirmed} |\n`
  out += `| Files Indexed | ${filesIndexed} |\n`
  out += `| Functions Indexed | ${functionsIndexed} |\n`
  out += `| Lines of Code | ${linesOfCode} |\n\n`

  out += "### Candidates by Type (leads, not verdicts)\n\n"
  const entries = Object.entries(candidatesByType).filter(([, count]) => (count as number) > 0)
  if (entries.length === 0) {
    out += "本轮无收敛候选。\n\n"
  } else {
    out += "| Skill | Count |\n"
    out += "|-------|-------|\n"
    for (const [vt, count] of entries) {
      out += `| ${vt} | ${count} |\n`
    }
    out += "\n"
  }

  const autoEntries = Object.entries(autoConfirmedByType).filter(([, count]) => (count as number) > 0)
  if (autoEntries.length > 0) {
    out += "### Auto-confirmed by Type (machine-proved, needs AI re-review)\n\n"
    out += "| Skill | Count |\n"
    out += "|-------|-------|\n"
    for (const [vt, count] of autoEntries) {
      out += `| ${vt} | ${count} |\n`
    }
    out += "\n"
  }

  out += "### Output Files\n\n"
  out += `- Report: ${path.join(scanDir, "report.md")}\n`
  out += `- SARIF (candidate stage, unclassified): ${path.join(scanDir, "candidates.sarif")}\n`
  out += `- SARIF (verdict stage, after classification): ${path.join(scanDir, "result.sarif")}\n`
  out += `- Latest: ${path.join(workspace, ".codeagent", "secguard-clang", "scans", "latest")}\n`

  w.write(out)
}

// withKill bounds the scan subprocess and TERMINATES it on expiry (the old
// wrapper awaited .text() with no timeout at all, so a large-repo scan could
// hang past every host budget and lose scan_id/output_dir on host timeout).
async function withKill(proc: { text(): Promise<string>, kill(): void }, ms: number, label: string): Promise<string> {
  const timer = setTimeout(() => { try { proc.kill() } catch { /* already exited */ } }, ms)
  try {
    return await proc.text()
  } catch (e: any) {
    throw new Error(`${label} outcome_unknown after ${ms}ms (subprocess killed; recover with secguard_status --per-type, never by blind rescan): ${e?.message || e}`)
  } finally {
    clearTimeout(timer)
  }
}

export default tool({
  description:
    "Run full SecGuard security scan: index codebase, run all registered detectors, apply the convergence pipeline for every registered vulnerability type. Writes report.md (summary + per-type counts) + candidates.sarif (unclassified leads at SARIF level note) + per-type candidate indexes (candidates/<vuln-type>/_index.md, the Source/Hint/Evidence table the AI classifies from) + candidate evidence Markdown to .codeagent/secguard-clang/scans/<scan_id>/; findings/<vuln-type>/ and result.sarif are produced later from the AI verdicts via secguard_report, stores DB at .codeagent/secguard-clang/.sgre/sgre.db. Returns JSON with scan_id, output_dir, total_candidates, auto_confirmed_count, auto_confirmed_by_type (per-type machine-confirmed counts — a type with 0 candidates but auto_confirmed_by_type > 0 still needs an AI re-review subagent), candidates_by_type, seeds_by_type, plan_errors, detector_errors, detectors_skipped (the detector switch actually applied from [scan] skip_detectors / --skip-detectors — a skipped detector's vuln types read 0 candidates by switch, not by clean code), files_indexed/functions_indexed/lines_of_code (scan scale), index_summary/scan_metrics/completion_state/incomplete_task_count/disabled_types. The Go binary generates scan_id, creates the scan directory, and updates the latest symlink — this wrapper only invokes the binary and parses its JSON output.",
  args: {
    path: tool.schema
      .string()
      .optional()
      .describe("Target path to scan. Defaults to current workspace root."),
    types: tool.schema
      .array(tool.schema.string())
      .optional()
      .describe("Optional type filter (kebab-case vuln types, e.g. [\"null-deref\",\"buffer-overflow\"]). Forwarded as the CLI's [type-filter] positional argument: a filtered scan runs ONLY these types instead of paying for the whole registry."),
    timeout_ms: tool.schema
      .number()
      .optional()
      .describe("Scan wall-clock budget in milliseconds (default 600000 = 10 min, per F4 for repos > 100 C files). On expiry the subprocess is KILLED and the result is outcome_unknown — recover with secguard_status, not a blind rescan."),
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
      // Do NOT pass --output-dir: the Go binary generates the scan_id, creates
      // the scan directory, writes SARIF/report.md/scan.log, and updates the
      // latest symlink atomically. This wrapper reads scan_id and scan_dir
      // from the binary's JSON output so there is a single source of truth.
      const timeoutMs = args.timeout_ms && args.timeout_ms > 0 ? Math.floor(args.timeout_ms) : 600_000
      const typeFilter = args.types && args.types.length > 0 ? args.types.join(",") : ""
      const result = await withKill(Bun.$`${secguardBin} scan --db ${dbPath} ${targetPath} ${typeFilter}`
        .cwd(workDir)
        .quiet(), timeoutMs, "secguard scan")

      try {
        const goJson = JSON.parse(result.trim())
        const scanId = goJson?.scan_id ?? ""
        const scanDir = goJson?.scan_dir ?? ""
        const totalCandidates = goJson?.total_candidates ?? 0
        const filesIndexed = goJson?.index_summary?.files_indexed ?? 0
        const functionsIndexed = goJson?.index_summary?.functions_indexed ?? 0
        const linesOfCode = goJson?.index_summary?.lines_of_code ?? 0
        const autoConfirmed = goJson?.auto_confirmed_count ?? 0
        const candidatesByType = goJson?.candidates_by_type ?? {}
        const autoConfirmedByType = goJson?.auto_confirmed_by_type ?? {}
        const seedsByType = goJson?.seeds_by_type ?? {}
        const planErrors = goJson?.plan_errors ?? {}
        const detectorErrors = goJson?.detector_errors ?? {}
        const detectorsSkipped = goJson?.detectors_skipped ?? []
        printScanSummary(process.stderr, goJson, targetPath, workDir)

        const reportError = goJson?.report_error ?? ""

        const typeCounts: Record<string, number> = {}
        if (candidatesByType && typeof candidatesByType === "object") {
          for (const [vt, count] of Object.entries(candidatesByType)) {
            typeCounts[vt] = count as number
          }
        }

        const reportMdPath = path.join(scanDir, "report.md")
        const response: Record<string, any> = {
          scan_id: scanId,
          output_dir: scanDir,
          report_md: reportMdPath,
          // The scan produces the candidate-stage SARIF; result.sarif is the
          // verdict-stage file, written by `secguard report --audit` once
          // findings are persisted, so it does not exist yet.
          candidates_sarif: path.join(scanDir, "candidates.sarif"),
          sarif: path.join(scanDir, "result.sarif"),
          db_path: dbPath,
          total_candidates: totalCandidates,
          files_indexed: filesIndexed,
          functions_indexed: functionsIndexed,
          lines_of_code: linesOfCode,
          auto_confirmed_count: autoConfirmed,
          auto_confirmed_by_type: autoConfirmedByType,
          candidates_by_type: typeCounts,
          seeds_by_type: seedsByType,
          plan_errors: planErrors,
          detector_errors: detectorErrors,
          detectors_skipped: detectorsSkipped,
          target_path: targetPath,
          // The orchestrator's scale/timeout/completion contract needs the FULL
          // envelope, not just the flattened top-level counts.
          index_summary: goJson?.index_summary,
          scan_metrics: goJson?.scan_metrics,
          scan_scope: goJson?.scan_scope,
          completion_state: goJson?.completion_state,
          incomplete_task_count: goJson?.incomplete_task_count,
          incomplete_tasks: goJson?.incomplete_tasks,
          disabled_types: goJson?.disabled_types,
        }
        // 强制落盘验证：检查 report.md 实际存在且非空。如果不存在或为空，
        // 覆盖 report_error 让 agent 知道落盘失败，不要去读不存在的文件。
        if (reportError) {
          response.report_error = reportError
        } else {
          try {
            const stat = fs.statSync(reportMdPath)
            if (stat.size === 0) {
              response.report_error = `report.md is empty at ${reportMdPath} — scan output was not persisted.`
            }
          } catch {
            response.report_error = `report.md not found at ${reportMdPath} — scan may have completed but output was not persisted.`
          }
        }
        return JSON.stringify(response, null, 2)
      } catch {
        // JSON.parse 失败时，绝不返回原始 result（可能含完整 evidence_packages，
        // 达 100KB+ 会触发 OpenCode 截断并存到 ~/.local/share/opencode/tool-output/，
        // 诱导 agent 去读那个截断文件并触发权限弹窗）。改用正则提取 scan_id/scan_dir，
        // 返回精简信息——agent 通过 candidates/<type>/_index.md 获取完整候选列表（见 agent-body.md）。
        const m = (re: RegExp) => result.match(re)?.[1] ?? ""
        const scanId = m(/"scan_id"\s*:\s*"([^"]+)"/)
        const scanDir = m(/"scan_dir"\s*:\s*"([^"]+)"/)
        if (scanDir) {
          // A degraded response must NOT look like a successful scan: without
          // candidates_by_type/total_candidates the scale gate could read an
          // unknown scale as 0 and skip the whole AI stage. The caller must
          // recover the real scale via secguard_status / secguard_metrics.
          return JSON.stringify({
            status: "error",
            recoverable: true,
            error: "scan output JSON was too large to parse inline; scale is UNKNOWN — recover candidates_by_type/total_candidates via secguard_status --per-type and secguard_metrics before continuing (do NOT treat this as a completed scan)",
            scan_id: scanId,
            output_dir: scanDir,
            report_md: path.join(scanDir, "report.md"),
            candidates_sarif: path.join(scanDir, "candidates.sarif"),
            db_path: dbPath,
            target_path: targetPath,
          }, null, 2)
        }
        return JSON.stringify({ error: "Scan output unparseable; check candidates/<type>/_index.md in the scan directory.", db_path: dbPath, target_path: targetPath }, null, 2)
      }
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: "Scan failed: " + err, db_path: dbPath, target_path: targetPath, workspace: workDir }, null, 2)
    }
  },
})
