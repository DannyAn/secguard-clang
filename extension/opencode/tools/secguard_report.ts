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
    "Write security findings to the SecGuard database (sgre.db) or retrieve existing findings. When findings argument is provided, writes them to the database and generates an audit report. When no findings argument, returns all existing findings as JSON.",
  args: {
    findings: tool.schema
      .array(
        tool.schema.object({
          rule_id: tool.schema.string().describe("Rule identifier, e.g. CWE-476"),
          severity: tool.schema
            .string()
            .describe("Severity: CRITICAL, HIGH, MEDIUM, LOW"),
          confidence: tool.schema
            .number()
            .min(0)
            .max(100)
            .describe("Confidence score 0-100"),
          status: tool.schema
            .string()
            .describe("Status: confirmed, suspected, dismissed"),
          file: tool.schema.string().describe("Source file path"),
          line: tool.schema.number().describe("Source line number"),
          function: tool.schema.string().describe("Function name"),
          variable: tool.schema.string().optional().describe("Variable name"),
          evidence: tool.schema
            .string()
            .describe("Human-readable evidence summary"),
          suggestion: tool.schema
            .string()
            .optional()
            .describe("Suggested fix"),
        })
      )
      .optional()
      .describe(
        "Findings to write. If omitted, returns all existing findings from the database."
      ),
    scan_id: tool.schema
      .string()
      .optional()
      .describe("Scan ID to associate findings with (for audit report generation)."),
    output_dir: tool.schema
      .string()
      .optional()
      .describe("Output directory for audit report. If provided, audit-report.md is generated after writing findings."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const sgreDir = path.join(workDir, ".codeagent", "secguard-clang", ".sgre")
    if (!fs.existsSync(sgreDir)) fs.mkdirSync(sgreDir, { recursive: true })
    const dbPath = path.join(sgreDir, "sgre.db")

    if (args.findings && args.findings.length > 0) {
      const errors: string[] = []
      let skipped = 0
      const scanId = args.scan_id || ""
      for (const finding of args.findings) {
        const props = JSON.stringify({
          variable: finding.variable || "",
          suggestion: finding.suggestion || "",
        })
        try {
          const report = scanId
            ? Bun.$`${secguardBin} report --db ${dbPath} --write --rule-id ${finding.rule_id} --severity ${finding.severity.toLowerCase()} --confidence ${String(finding.confidence)} --status ${finding.status} --file ${finding.file} --line ${String(finding.line)} --function ${finding.function} --evidence ${finding.evidence} --properties ${props} --scan-id ${scanId}`
            : Bun.$`${secguardBin} report --db ${dbPath} --write --rule-id ${finding.rule_id} --severity ${finding.severity.toLowerCase()} --confidence ${String(finding.confidence)} --status ${finding.status} --file ${finding.file} --line ${String(finding.line)} --function ${finding.function} --evidence ${finding.evidence} --properties ${props}`
          await report.cwd(workDir).quiet().text()
        } catch (e: any) {
          const msg = e?.stderr?.toString()?.trim() || e?.message || String(e)
          errors.push(`${finding.file}:${finding.line} — ${msg}`)
          skipped++
        }
      }

      let auditPath: string | undefined
      if (args.output_dir && scanId) {
        try {
          const auditResult = await Bun.$`${secguardBin} report --db ${dbPath} --audit --scan-id ${scanId} --output-dir ${args.output_dir}`
            .cwd(workDir)
            .quiet()
            .text()
          const auditJson = JSON.parse(auditResult.trim())
          auditPath = auditJson.audit_path
        } catch {
          // Best-effort — audit report generation failure is non-fatal
        }
      }

      return JSON.stringify(
        { status: errors.length === 0 ? "ok" : "partial", findings_written: args.findings.length - errors.length, skipped, audit_path: auditPath, errors },
        null,
        2
      )
    }

    const result = await Bun.$`${secguardBin} report --db ${dbPath}`
      .cwd(workDir)
      .quiet()
      .text()
      .catch((e: any) => {
        const err = e?.stderr?.toString()?.trim() || ""
        return JSON.stringify({ findings: [], error: err })
      })

    return result.trim()
  },
})
