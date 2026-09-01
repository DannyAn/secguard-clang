import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import { randomUUID } from "crypto"

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
    "Write security findings to the SecGuard database (sgre.db), retrieve existing findings, or record an optional post-hoc override verdict for a finding. When findings is provided, writes them and returns each finding's database id. When reviews is provided, records --review verdicts (confirmed|dismissed|suspected-kept). When neither is provided, returns all existing findings as JSON. Pass scan_id AND output_dir whenever you write or review: they place each verdict file under findings/<vuln-type>/NNN_<file>_<line>_<confirmed|suspected>.md and re-sync that directory with the database. Dismissed findings intentionally get no file there. Any per_finding_warning in the response means the verdict did not reach findings/ — fix the call and write again.",
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
            .describe("Optional post-hoc override: confirmed, dismissed, or suspected-kept"),
          review_reasoning: tool.schema
            .string()
            .describe("One-line justification for the override"),
        })
      )
      .optional()
      .describe(
        "Optional post-hoc override verdicts (each targets a finding id from a prior write)."
      ),
    scan_id: tool.schema
      .string()
      .optional()
      .describe("Scan ID to associate findings with (for audit report generation)."),
    output_dir: tool.schema
      .string()
      .optional()
      .describe("Output directory for audit report. If provided, report.md (regenerated from persisted findings showing confirmed+suspected), audit-report.md, and result.sarif are generated after writing findings."),
    finalize: tool.schema
      .boolean()
      .optional()
      .describe("Whether to regenerate report.md/result.sarif/result.xlsx/findings/ after this call. Defaults to true. For a large type split into many write chunks, pass false on every chunk except the last (or leave finalization to the orchestrator's single `report --audit`) to avoid re-rendering the whole report once per chunk."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const sgreDir = path.join(workDir, ".codeagent", "secguard-clang", ".sgre")
    if (!fs.existsSync(sgreDir)) fs.mkdirSync(sgreDir, { recursive: true })
    const dbPath = path.join(sgreDir, "sgre.db")
    const outputDir = args.output_dir || ""

    // Regenerates report.md (verdict-stage, confirmed+suspected) + audit-report.md
    // + result.sarif and re-syncs findings/ from the DB. Called after a write
    // batch AND after a review batch: a review (A5) changes EffectiveStatus, so
    // skipping the audit after reviews leaves result.sarif one revision behind
    // the database.
    const runAudit = async (scanId: string, outDir: string) => {
      try {
        const auditResult = await Bun.$`${secguardBin} report --db ${dbPath} --audit --scan-id ${scanId} --output-dir ${outDir}`
          .cwd(workDir)
          .quiet()
          .text()
        return JSON.parse(auditResult.trim())
      } catch {
        return null // Best-effort — audit generation failure is non-fatal
      }
    }

    if (args.findings && args.findings.length > 0) {
      const scanId = args.scan_id || ""

      // Batch mode: write the WHOLE type's findings in ONE `--write-json`
      // subprocess instead of a per-finding `--write` loop (which spawns one
      // subprocess + SQLite transaction per finding — the slow path the docs
      // warn against). The payload goes to the project's .sgre/.tmp (a runtime
      // artifact the scan step clears), never os.TempDir; a randomUUID name
      // keeps concurrent batch workers from clobbering each other's file.
      const tmpDir = path.join(sgreDir, ".tmp")
      if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true })
      const tmpFile = path.join(tmpDir, `write-${randomUUID()}.json`)
      const inputs = args.findings.map((finding) => ({
        rule_id: finding.rule_id,
        severity: finding.severity,
        confidence: finding.confidence,
        status: finding.status,
        file: finding.file,
        line: finding.line,
        function: finding.function,
        summary: finding.summary || "",
        reasoning: finding.reasoning || "",
        exception_check: finding.exception_check || "",
        fix_strategy: finding.fix_strategy || "",
      }))
      fs.writeFileSync(tmpFile, JSON.stringify(inputs))

      const written: { file: string; line: number; id: number }[] = []
      const errors: string[] = []
      const perFindingWarnings: string[] = []
      let skipped = 0
      try {
        const out = (await Bun.$`${secguardBin} report --db ${dbPath} --write-json ${tmpFile} --scan-id=${scanId}`
          .cwd(workDir)
          .quiet()
          .text()
        ).trim()
        try {
          const parsed = JSON.parse(out)
          for (const w of parsed.written ?? []) {
            if (typeof w.id === "number") {
              written.push({ file: w.file, line: w.line, id: w.id })
            }
          }
          // Per-item failures (unsupported rule_id, empty rule_id, DB error)
          // come back as strings in `errors`; each is one un-written finding.
          for (const e of parsed.errors ?? []) {
            errors.push(String(e))
            skipped++
          }
        } catch {
          errors.push("unparseable --write-json response")
        }
      } catch (e: any) {
        const msg = e?.stderr?.toString()?.trim() || e?.message || String(e)
        errors.push(`batch write failed: ${msg}`)
        skipped = args.findings.length
      } finally {
        try { fs.unlinkSync(tmpFile) } catch {}
      }

      let auditPath: string | undefined
      let findingsSynced: unknown
      // `finalize` defaults to true (backward-compatible); a large type split
      // into many write chunks passes false on intermediate chunks so the whole
      // report is not re-rendered once per chunk — that per-chunk re-render was
      // the "output-then-look-it-up-again" work the speed pass removes.
      if (args.finalize !== false && outputDir && scanId) {
        const auditJson = await runAudit(scanId, outputDir)
        if (auditJson) {
          auditPath = auditJson.audit_path
          // The audit pass re-syncs findings/ with the database: it reports how
          // many verdict files were written and how many dismissed/unclassified
          // leftovers were swept out of the review surface.
          findingsSynced = auditJson.findings_synced
          if (auditJson.warning) perFindingWarnings.push(auditJson.warning)
        }
      }

      return JSON.stringify(
        {
          status: errors.length === 0 ? "ok" : "partial",
          findings_written: written.length,
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

      // Batch mode: record the WHOLE A5 review pass in ONE `--review-json`
      // subprocess + one SQLite transaction, instead of the per-finding
      // `--review` loop (which spawns a subprocess + opens SQLite per row — the
      // slow path that stretched a high-volume type like null-deref to tens of
      // minutes). The payload goes to the same .sgre/.tmp runtime dir as the
      // write batch; a randomUUID name keeps concurrent workers from clobbering.
      const tmpDir = path.join(sgreDir, ".tmp")
      if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true })
      const tmpFile = path.join(tmpDir, `review-${randomUUID()}.json`)
      const reviewInputs = args.reviews.map((r) => ({
        id: r.id,
        review_status: r.review_status,
        review_reasoning: r.review_reasoning || "",
      }))
      fs.writeFileSync(tmpFile, JSON.stringify(reviewInputs))

      try {
        const out = (await Bun.$`${secguardBin} report --db ${dbPath} --review-json ${tmpFile}`
          .cwd(workDir)
          .quiet()
          .text()
        ).trim()
        try {
          const parsed = JSON.parse(out)
          for (const r of parsed.reviewed ?? []) {
            if (typeof r.id === "number") {
              reviewed.push({ id: r.id, review_status: r.review_status })
            }
          }
          for (const e of parsed.errors ?? []) {
            errors.push(String(e))
          }
        } catch {
          errors.push("unparseable --review-json response")
        }
      } catch (e: any) {
        const msg = e?.stderr?.toString()?.trim() || e?.message || String(e)
        errors.push(`batch review failed: ${msg}`)
      } finally {
        try { fs.unlinkSync(tmpFile) } catch {}
      }

      // A5 reviews change EffectiveStatus, so regenerate report.md + result.sarif
      // + audit-report.md + findings/ once after the batch — otherwise the SARIF
      // still shows the pre-review verdicts (e.g. dismissed entries lingering
      // as `warning`).
      let auditPath: string | undefined
      let findingsSynced: unknown
      if (args.finalize !== false && outputDir && args.scan_id) {
        const auditJson = await runAudit(args.scan_id, outputDir)
        if (auditJson) {
          auditPath = auditJson.audit_path
          findingsSynced = auditJson.findings_synced
          if (auditJson.warning) reviewWarnings.push(auditJson.warning)
        }
      }

      return JSON.stringify(
        {
          status: errors.length === 0 ? "ok" : "partial",
          reviewed,
          errors,
          audit_path: auditPath,
          findings_synced: findingsSynced,
          per_finding_warnings: reviewWarnings,
        },
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
