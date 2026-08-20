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
    "Write security findings to the SecGuard database (sgre.db), retrieve existing findings, or record a second-round (A5) review verdict for a suspected finding. When findings is provided, writes them and returns each finding's database id (needed later for review). When reviews is provided, records --review verdicts (confirmed|dismissed|suspected-kept). When neither is provided, returns all existing findings as JSON.",
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
            .describe("Human-readable evidence summary (source/sink/path/condition)"),
          summary: tool.schema
            .string()
            .optional()
            .describe("One-paragraph summary of the vulnerability and its impact"),
          reasoning: tool.schema
            .string()
            .optional()
            .describe("The full reasoning chain: why this is a real vulnerability (or not)"),
          exception_check: tool.schema
            .string()
            .optional()
            .describe("Exception check: RAII / ownership-transfer / safe-wrapper / guard rules that were ruled out"),
          fix_strategy: tool.schema
            .string()
            .optional()
            .describe("Concrete fix strategy, ideally with a code snippet"),
          suggestion: tool.schema
            .string()
            .optional()
            .describe("Short one-line suggested fix"),
        })
      )
      .optional()
      .describe(
        "Findings to write. If omitted and reviews is omitted, returns all existing findings from the database."
      ),
    reviews: tool.schema
      .array(
        tool.schema.object({
          id: tool.schema.number().describe("Finding id returned by a previous write"),
          review_status: tool.schema
            .string()
            .describe("Second-round verdict: confirmed, dismissed, or suspected-kept"),
          review_reasoning: tool.schema
            .string()
            .describe("One-line justification for the second-round call"),
        })
      )
      .optional()
      .describe(
        "A5 second-round review verdicts for suspected findings (each targets a finding id from a prior write)."
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
      const written: { file: string; line: number; id: number }[] = []
      for (const finding of args.findings) {
        // Structured AI output (summary/reasoning/fix_strategy/exception_check)
        // rides inside the properties JSON rather than as separate CLI flags:
        // JSON.stringify escapes newlines to \n, so the payload is always a
        // single line and survives Bun's argument escaping regardless of how
        // multi-line the reasoning/fix code is.
        const props = JSON.stringify({
          variable: finding.variable || "",
          suggestion: finding.suggestion || "",
          summary: finding.summary || "",
          reasoning: finding.reasoning || "",
          fix_strategy: finding.fix_strategy || "",
          exception_check: finding.exception_check || "",
        })
        try {
          const report = scanId
            ? Bun.$`${secguardBin} report --db ${dbPath} --write --rule-id ${finding.rule_id} --severity ${finding.severity.toLowerCase()} --confidence ${String(finding.confidence)} --status ${finding.status} --file ${finding.file} --line ${String(finding.line)} --function ${finding.function} --evidence ${finding.evidence} --properties ${props} --scan-id ${scanId}`
            : Bun.$`${secguardBin} report --db ${dbPath} --write --rule-id ${finding.rule_id} --severity ${finding.severity.toLowerCase()} --confidence ${String(finding.confidence)} --status ${finding.status} --file ${finding.file} --line ${String(finding.line)} --function ${finding.function} --evidence ${finding.evidence} --properties ${props}`
          const out = (await report.cwd(workDir).quiet().text()).trim()
          // The CLI returns {"id": N, "status":"ok", ...}. Capture the id so the
          // agent can later issue a second-round --review for this exact finding.
          try {
            const parsed = JSON.parse(out)
            if (typeof parsed.id === "number") {
              written.push({ file: finding.file, line: finding.line, id: parsed.id })
            }
          } catch {
            // Non-JSON stdout — best effort, treat as success but no id captured.
          }
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
        { status: errors.length === 0 ? "ok" : "partial", findings_written: args.findings.length - errors.length, skipped, written, audit_path: auditPath, errors },
        null,
        2
      )
    }

    if (args.reviews && args.reviews.length > 0) {
      const errors: string[] = []
      const reviewed: { id: number; review_status: string }[] = []
      for (const review of args.reviews) {
        try {
          const out = (await Bun.$`${secguardBin} report --db ${dbPath} --review --id ${String(review.id)} --review-status ${review.review_status} --review-reasoning ${review.review_reasoning || ""}`
            .cwd(workDir)
            .quiet()
            .text()
          ).trim()
          JSON.parse(out) // throws if the CLI returned a non-JSON error, caught below
          reviewed.push({ id: review.id, review_status: review.review_status })
        } catch (e: any) {
          const msg = e?.stderr?.toString()?.trim() || e?.message || String(e)
          errors.push(`finding ${review.id} — ${msg}`)
        }
      }
      return JSON.stringify(
        { status: errors.length === 0 ? "ok" : "partial", reviewed, errors },
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
