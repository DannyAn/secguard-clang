import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import crypto from "crypto"

function findSecguard(context: { worktree?: string, directory?: string }): string {
  let dir = context.worktree || context.directory || "."
  if (dir === "/") dir = "."
  const bundled = path.join(dir, ".opencode/bin/secguard")
  if (fs.existsSync(bundled)) return bundled
  return "secguard"
}

function generateScanId(): string {
  const now = new Date()
  const pad = (n: number) => String(n).padStart(2, "0")
  const ts = `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}${pad(now.getSeconds())}`
  const suffix = crypto.randomBytes(2).toString("hex")
  return `${ts}_${suffix}`
}

function updateLatestSymlink(scansDir: string, scanId: string): void {
  const target = scanId
  const tmpName = `.latest.tmp.${process.pid}`
  const tmpPath = path.join(scansDir, tmpName)
  const latestPath = path.join(scansDir, "latest")
  try {
    try { fs.unlinkSync(tmpPath) } catch {}
    fs.symlinkSync(target, tmpPath)
    fs.renameSync(tmpPath, latestPath)
    try { fs.unlinkSync(path.join(scansDir, "latest.txt")) } catch {}
  } catch {
    try {
      const txtTmp = path.join(scansDir, `.latest.txt.tmp.${process.pid}`)
      fs.writeFileSync(txtTmp, scanId)
      fs.renameSync(txtTmp, path.join(scansDir, "latest.txt"))
      try { fs.unlinkSync(latestPath) } catch {}
    } catch (e2) {
      process.stderr.write(`warning: failed to update latest pointer: ${e2}\n`)
    }
  }
}

const CWE_MAP: Record<string, string> = {
  "null-deref": "CWE-476",
  "buffer-overflow": "CWE-787",
  "memory-leak": "CWE-401",
  "injection": "CWE-78",
  "resource-leak": "CWE-404",
  "uninit": "CWE-457",
  "use-after-free": "CWE-416",
  "double-free": "CWE-415",
  "format-string": "CWE-134",
  "integer-overflow": "CWE-190",
  "race-condition": "CWE-362",
  "hardcoded-secret": "CWE-798",
  "deadlock": "CWE-667",
  "crypto-misuse": "CWE-327",
}

function cweForType(vulnType: string): string {
  return CWE_MAP[vulnType] ?? "CWE-Other"
}

function printScanSummary(
  w: { write(s: string): boolean },
  goJson: any,
  targetPath: string,
  workspace: string,
  outputDir: string,
): void {
  const scanId = goJson?.scan_id ?? "N/A"
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
  out += `| Scan Dir | ${outputDir} |\n`
  out += `| Total Candidates | ${totalCandidates} |\n`
  out += `| Files Indexed | ${filesIndexed} |\n`
  out += `| Functions Indexed | ${functionsIndexed} |\n\n`

  out += "### Candidates by Type\n\n"
  const nonEmpty = packages.filter((p: any) => p?.candidates?.length > 0)
  if (nonEmpty.length === 0) {
    out += "No issues found.\n\n"
  } else {
    out += "| Type | CWE | Count |\n"
    out += "|------|-----|-------|\n"
    for (const p of nonEmpty) {
      const vt = p?.vulnerability_type ?? "unknown"
      const count = p?.candidates?.length ?? 0
      out += `| ${vt} | ${cweForType(vt)} | ${count} |\n`
    }
    out += "\n"
  }

  out += "### Output Files\n\n"
  out += `- Report: ${path.join(outputDir, "report.md")}\n`
  out += `- SARIF: ${path.join(outputDir, "sarif.sarif")}\n`
  out += `- Latest: ${path.join(workspace, ".codeagent", "zhuque-secguard", "scans", "latest")}\n`

  w.write(out)
}

export default tool({
  description:
    "Run full SecGuard security scan: index codebase, run all 17 detectors, apply convergence pipeline for all 14 vulnerability types. Writes SARIF 2.1 + report.md + per-finding Markdown to .codeagent/zhuque-secguard/scans/<scan_id>/, stores DB at .codeagent/zhuque-secguard/.sgre/sgre.db. Returns JSON with evidence_packages, total_candidates, files_with_candidates, output_dir.",
  args: {
    path: tool.schema
      .string()
      .optional()
      .describe("Target path to scan. Defaults to current workspace root."),
  },
  async execute(args, context) {
    let workDir = context.worktree || context.directory || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const targetPath = args.path || workDir

    const sgreDir = path.join(workDir, ".codeagent", "zhuque-secguard", ".sgre")
    if (!fs.existsSync(sgreDir)) fs.mkdirSync(sgreDir, { recursive: true })
    const dbPath = path.join(sgreDir, "sgre.db")

    const scanId = generateScanId()
    const outputDir = path.join(workDir, ".codeagent", "zhuque-secguard", "scans", scanId)
    fs.mkdirSync(outputDir, { recursive: true })

    try {
      const result = await Bun.$`${secguardBin} scan --db ${dbPath} --output-dir ${outputDir} ${targetPath}`
        .cwd(workDir)
        .quiet()
        .text()

      const scansDir = path.join(workDir, ".codeagent", "zhuque-secguard", "scans")
      updateLatestSymlink(scansDir, scanId)

      try {
        const goJson = JSON.parse(result.trim())
        printScanSummary(process.stderr, goJson, targetPath, workDir, outputDir)
        const summaryFromGo = typeof goJson?._summary === "string" ? goJson._summary : undefined

        const summary = JSON.stringify({
          output_dir: outputDir,
          sarif: path.join(outputDir, "sarif.sarif"),
          report_md: path.join(outputDir, "report.md"),
          db_path: dbPath,
          scan_id: scanId,
          raw: result.trim(),
          target_path: targetPath,
          workspace: workDir,
          _summary: summaryFromGo,
        }, null, 2)
        return summary
      } catch {
        return JSON.stringify({
          output_dir: outputDir,
          sarif: path.join(outputDir, "sarif.sarif"),
          report_md: path.join(outputDir, "report.md"),
          db_path: dbPath,
          scan_id: scanId,
          raw: result.trim(),
          target_path: targetPath,
          workspace: workDir,
          _summary: undefined,
        }, null, 2)
      }
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: "Scan failed: " + err, db_path: dbPath, output_dir: outputDir, target: targetPath, target_path: targetPath, workspace: workDir }, null, 2)
    }
  },
})
