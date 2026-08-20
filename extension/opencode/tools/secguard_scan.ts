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
  const packages = goJson?.evidence_packages ?? []

  let out = "## SecGuard Scan Summary\n\n"
  out += "| Field | Value |\n"
  out += "|-------|-------|\n"
  out += `| Scan ID | ${scanId} |\n`
  out += `| Target | ${targetPath} |\n`
  out += `| Workspace | ${workspace} |\n`
  out += `| Scan Dir | ${scanDir} |\n`
  out += `| Total Candidates | ${totalCandidates} |\n`
  out += `| Files Indexed | ${filesIndexed} |\n`
  out += `| Functions Indexed | ${functionsIndexed} |\n\n`

  out += "### Candidates by Type\n\n"
  const nonEmpty = packages.filter((p: any) => p?.candidates?.length > 0)
  if (nonEmpty.length === 0) {
    out += "No issues found.\n\n"
  } else {
    out += "| Skill | CWE | Count |\n"
    out += "|-------|-----|-------|\n"
    for (const p of nonEmpty) {
      const vt = p?.vulnerability_type ?? "unknown"
      const cwe = p?.cwe ?? "CWE-Other"
      const count = p?.candidates?.length ?? 0
      out += `| ${vt} | ${cwe} | ${count} |\n`
    }
    out += "\n"
  }

  out += "### Output Files\n\n"
  out += `- Report: ${path.join(scanDir, "report.md")}\n`
  out += `- SARIF: ${path.join(scanDir, "result.sarif")}\n`
  out += `- Latest: ${path.join(workspace, ".codeagent", "secguard-clang", "scans", "latest")}\n`

  w.write(out)
}

export default tool({
  description:
    "Run full SecGuard security scan: index codebase, run all registered detectors, apply the convergence pipeline for every registered vulnerability type. Writes SARIF 2.1 + report.md + per-finding Markdown to .codeagent/secguard-clang/scans/<scan_id>/, stores DB at .codeagent/secguard-clang/.sgre/sgre.db. Returns JSON with evidence_packages, total_candidates, files_with_candidates, output_dir. The Go binary generates scan_id, creates the scan directory, and updates the latest symlink — this wrapper only invokes the binary and parses its JSON output.",
  args: {
    path: tool.schema
      .string()
      .optional()
      .describe("Target path to scan. Defaults to current workspace root."),
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
      const result = await Bun.$`${secguardBin} scan --db ${dbPath} ${targetPath}`
        .cwd(workDir)
        .quiet()
        .text()

      try {
        const goJson = JSON.parse(result.trim())
        const scanId = goJson?.scan_id ?? ""
        const scanDir = goJson?.scan_dir ?? ""
        const totalCandidates = goJson?.total_candidates ?? 0
        const filesIndexed = goJson?.index_summary?.files_indexed ?? 0
        const functionsIndexed = goJson?.index_summary?.functions_indexed ?? 0
        const packages = goJson?.evidence_packages ?? []
        const candidatesByType = goJson?.candidates_by_type ?? {}
        printScanSummary(process.stderr, goJson, targetPath, workDir)

        const reportError = goJson?.report_error ?? ""

        const typeCounts: Record<string, number> = {}
        // 优先用 Go 提供的 candidates_by_type 摘要；回退到 evidence_packages（向后兼容）
        if (candidatesByType && typeof candidatesByType === "object" && Object.keys(candidatesByType).length > 0) {
          for (const [vt, count] of Object.entries(candidatesByType)) {
            typeCounts[vt] = count as number
          }
        } else {
          for (const p of packages) {
            const vt = p?.vulnerability_type ?? "unknown"
            typeCounts[vt] = p?.candidates?.length ?? 0
          }
        }

        const reportMdPath = path.join(scanDir, "report.md")
        const response: Record<string, any> = {
          scan_id: scanId,
          output_dir: scanDir,
          report_md: reportMdPath,
          sarif: path.join(scanDir, "result.sarif"),
          db_path: dbPath,
          total_candidates: totalCandidates,
          files_indexed: filesIndexed,
          functions_indexed: functionsIndexed,
          candidates_by_type: typeCounts,
          target_path: targetPath,
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
        // 返回精简信息——agent 通过 report.md 获取完整候选列表（见 agent-body.md）。
        const m = (re: RegExp) => result.match(re)?.[1] ?? ""
        const scanId = m(/"scan_id"\s*:\s*"([^"]+)"/)
        const scanDir = m(/"scan_dir"\s*:\s*"([^"]+)"/)
        if (scanDir) {
          return JSON.stringify({
            scan_id: scanId,
            output_dir: scanDir,
            report_md: path.join(scanDir, "report.md"),
            sarif: path.join(scanDir, "result.sarif"),
            db_path: dbPath,
            target_path: targetPath,
            warning: "Scan completed but JSON was too large to parse inline. Read report.md for the full candidate list.",
          }, null, 2)
        }
        return JSON.stringify({ error: "Scan output unparseable; check report.md in the scan directory.", db_path: dbPath, target_path: targetPath }, null, 2)
      }
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: "Scan failed: " + err, db_path: dbPath, target_path: targetPath, workspace: workDir }, null, 2)
    }
  },
})
