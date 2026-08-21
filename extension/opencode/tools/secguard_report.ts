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
    "Write security findings to the SecGuard database (sgre.db), retrieve existing findings, or record a second-round (A5) review verdict for a suspected finding. When findings is provided, writes them and returns each finding's database id (needed later for review). When reviews is provided, records --review verdicts (confirmed|dismissed|suspected-kept). When neither is provided, returns all existing findings as JSON. Pass scan_id AND output_dir whenever you write or review: they place each verdict file under findings/<vuln-type>/NNN_<file>_<line>_<confirmed|suspected>.md and re-sync that directory with the database. Dismissed findings intentionally get no file there. Any per_finding_warning in the response means the verdict did not reach findings/ — fix the call and write again.",
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
          summary: tool.schema
            .string()
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
    const outputDir = args.output_dir || ""

    if (args.findings && args.findings.length > 0) {
      const errors: string[] = []
      const perFindingWarnings: string[] = []
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
          summary: finding.summary || "",
          reasoning: finding.reasoning || "",
          fix_strategy: finding.fix_strategy || "",
          exception_check: finding.exception_check || "",
        })
        try {
          // --output-dir is what lets the CLI place the verdict file under
          // findings/<vuln-type>/; without it the per-finding markdown is
          // skipped and the review surface silently drifts from the DB.
          // Both optional flags use the --flag=value form so an empty value is
          // parsed as "absent" — one command shape, no conditional branches.
          const out = (await Bun.$`${secguardBin} report --db ${dbPath} --write --rule-id ${finding.rule_id} --severity ${finding.severity.toLowerCase()} --confidence ${String(finding.confidence)} --status ${finding.status} --file ${finding.file} --line ${String(finding.line)} --function ${finding.function} --properties ${props} --scan-id=${scanId} --output-dir=${outputDir}`
            .cwd(workDir)
            .quiet()
            .text()
          ).trim()
          // The CLI returns {"id": N, "status":"ok", ...}. Capture the id so the
          // agent can later issue a second-round --review for this exact finding.
          try {
            const parsed = JSON.parse(out)
            if (typeof parsed.id === "number") {
              written.push({ file: finding.file, line: finding.line, id: parsed.id })
            }
            if (parsed.per_finding_warning) {
              perFindingWarnings.push(`${finding.file}:${finding.line} — ${parsed.per_finding_warning}`)
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
      let findingsSynced: unknown
      if (outputDir && scanId) {
        try {
          const auditResult = await Bun.$`${secguardBin} report --db ${dbPath} --audit --scan-id ${scanId} --output-dir ${outputDir}`
            .cwd(workDir)
            .quiet()
            .text()
          const auditJson = JSON.parse(auditResult.trim())
          auditPath = auditJson.audit_path
          // The audit pass re-syncs findings/ with the database: it reports how
          // many verdict files were written and how many dismissed/unclassified
          // leftovers were swept out of the review surface.
          findingsSynced = auditJson.findings_synced
          if (auditJson.warning) perFindingWarnings.push(auditJson.warning)
        } catch {
          // Best-effort — audit report generation failure is non-fatal
        }
      }

      return JSON.stringify(
        {
          status: errors.length === 0 ? "ok" : "partial",
          findings_written: args.findings.length - errors.length,
          skipped,
          written,
          audit_path: auditPath,
          findings_synced: findingsSynced,
          errors,
          // Non-empty means those verdicts never reached findings/<vuln-type>/:
          // re-issue the write with scan_id + output_dir.
          per_finding_warnings: perFindingWarnings,
        },
        null,
        2
      )
    }

    if (args.reviews && args.reviews.length > 0) {
      const errors: string[] = []
      const reviewWarnings: string[] = []
      const reviewed: { id: number; review_status: string }[] = []
      for (const review of args.reviews) {
        try {
          // The A5 verdict also rewrites (or removes) the verdict file, so the
          // review needs the scan directory just like the write does.
          const out = (await Bun.$`${secguardBin} report --db ${dbPath} --review --id ${String(review.id)} --review-status ${review.review_status} --review-reasoning ${review.review_reasoning || ""} --output-dir=${outputDir}`
            .cwd(workDir)
            .quiet()
            .text()
          ).trim()
          const parsed = JSON.parse(out) // throws if the CLI returned a non-JSON error, caught below
          if (parsed.per_finding_warning) {
            reviewWarnings.push(`finding ${review.id} — ${parsed.per_finding_warning}`)
          }
          reviewed.push({ id: review.id, review_status: review.review_status })
        } catch (e: any) {
          const msg = e?.stderr?.toString()?.trim() || e?.message || String(e)
          errors.push(`finding ${review.id} — ${msg}`)
        }
      }
      return JSON.stringify(
        { status: errors.length === 0 ? "ok" : "partial", reviewed, errors, per_finding_warnings: reviewWarnings },
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
