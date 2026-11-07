import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import { fileURLToPath } from "url"
import { randomUUID } from "crypto"

// withKill bounds a subprocess wait AND terminates the child on expiry: the
// old Promise.race only rejected the caller while the CLI kept running (and
// could still commit), leaving "caller saw failure, DB says success" splits.
// Killing first means the finally-cleanup (temp JSON) can never delete an
// input the CLI has not finished reading, and a timeout reads outcome_unknown
// (recover by querying the DB, never by blind rewrite).
async function withKill(proc: { text(): Promise<string>, kill(): void }, ms: number, label: string): Promise<string> {
  const timer = setTimeout(() => { try { proc.kill() } catch { /* already exited */ } }, ms)
  try {
    return await proc.text()
  } catch (e: any) {
    const msg = e?.message || String(e)
    throw new Error(`${label} outcome_unknown after ${ms}ms (subprocess killed; query status --per-type / findings before retrying): ${msg}`)
  } finally {
    clearTimeout(timer)
  }
}

// cliErrorJSON preserves the CLI's structured result even on a non-zero exit:
// --write-json/--audit print their JSON (written/errors/failed_details) BEFORE
// exiting 1, so catching only stderr used to mark a partially committed batch
// as a total failure and trigger a blind full rewrite.
function cliErrorJSON(e: any, fallback: Record<string, unknown>): Record<string, unknown> {
  const stdout = e?.stdout?.toString()?.trim() || ""
  if (stdout) {
    try { return { status: "partial", ...JSON.parse(stdout) } } catch { /* not JSON */ }
  }
  return { status: "error", ...fallback, error: e?.stderr?.toString()?.trim() || e?.message || String(e) }
}

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
    "Write security findings to the SecGuard database (sgre.db), or retrieve existing findings. When findings is provided, writes them as single-pass FINAL BINARY verdicts (confirmed|dismissed) and returns each finding's database id. When findings is omitted, returns all existing findings as JSON. Pass scan_id AND output_dir whenever you write: they place each verdict file under findings/<vuln-type>/NNN_<file>_<line>_confirmed.md and re-sync that directory with the database. Dismissed findings intentionally get no file there. Any per_finding_warning in the response means the verdict did not reach findings/ — fix the call and write again.",
  args: {
    action: tool.schema
      .enum(["write", "read", "audit", "complete_type", "stats"])
      .optional()
      .describe("Operation. write (default when findings is provided) persists verdicts; read lists findings (paginated); audit regenerates the terminal artifacts (report.md/audit-report.md/result.sarif/findings) and FAILS on any audit error instead of swallowing it; complete_type validates and closes one type's AI stage (requires vuln_type_arg + scan_id, fails 'incomplete' while ranges are uncovered); stats returns the read-only per-type verdict census."),
    vuln_type_arg: tool.schema
      .string()
      .optional()
      .describe("Vulnerability type for action=complete_type (e.g. null-deref)."),
    allow_partial: tool.schema
      .boolean()
      .optional()
      .describe("For action=audit: emit explicitly PARTIAL-labelled artifacts when some types' AI stage is unfinished. Without it, the audit hard-gates unfinished types."),
    db_path: tool.schema
      .string()
      .optional()
      .describe("Absolute path to sgre.db. Strongly recommended on every call: the subagent's cwd is not guaranteed to be the project root, and resolving the DB from the wrong directory reads/writes the wrong project."),
    limit: tool.schema
      .number()
      .optional()
      .describe("For action=read: page size (default 50). Large result sets are paginated, never dumped whole into context."),
    cursor: tool.schema
      .number()
      .optional()
      .describe("For action=read: zero-based offset of the next page (from the previous response's next_cursor)."),
    findings: tool.schema
      .array(
        tool.schema.object({
          rule_id: tool.schema.string().describe("Rule identifier, e.g. CWE-476"),
          vuln_type: tool.schema
            .string()
            .optional()
            .describe("Your dispatch type name (kebab-case, e.g. null-deref / divide-by-zero). REQUIRED for multi-CWE subclasses: a divide-by-zero int_min_div row carries rule_id CWE-190 but vuln_type divide-by-zero, never integer-overflow."),
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
            .describe("Status: confirmed, dismissed (binary — no suspected)"),
          file: tool.schema.string().describe("Source file path"),
          line: tool.schema.number().describe("Source line number"),
          function: tool.schema.string().describe("Function name"),
          variable: tool.schema
            .string()
            .optional()
            .describe("Sink/source variable the finding is about (dereferenced pointer, leaked allocation, divisor, …); copy from the candidate _index.md Variable column when present"),
          summary: tool.schema
            .string()
            .optional()
            .describe("One-paragraph summary of the vulnerability and its impact (required for confirmed; a dismissed row needs only reasoning)"),
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
        "Findings to write. If omitted, returns all existing findings from the database."
      ),
    scan_id: tool.schema
      .string()
      .optional()
      .describe("Scan ID to associate findings with (for audit report generation)."),
    output_dir: tool.schema
      .string()
      .optional()
      .describe("Output directory for audit report. If provided, report.md (regenerated from persisted findings showing confirmed only), audit-report.md, and result.sarif are generated after writing findings."),
    finalize: tool.schema
      .boolean()
      .optional()
      .describe("Whether to regenerate report.md/result.sarif/result.xlsx/findings/ after this call. Defaults to true. Leave it FALSE on EVERY write chunk of a large type, including the last one: the render is the orchestrator's single `secguard report --audit` at the end of the run, so a `finalize: true` chunk only duplicates that work and re-renders the whole report per chunk."),
    ai_duration_ms: tool.schema
      .number()
      .optional()
      .describe("OPTIONAL override for the AI-classification wall-clock in milliseconds. The engine already self-measures the AI stage from settlement report timestamps (audit-report.md AI Classification Timing / JSON ai_stage), so omit this on every normal run and pass it ONLY when the host cannot write settlement files."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const sgreDir = path.join(workDir, ".codeagent", "secguard-clang", ".sgre")
    if (!fs.existsSync(sgreDir)) fs.mkdirSync(sgreDir, { recursive: true })
    const dbPath = args.db_path || path.join(sgreDir, "sgre.db")
    const outputDir = args.output_dir || ""

    // Regenerates report.md (verdict-stage, confirmed only) + audit-report.md
    // + result.sarif and re-syncs findings/ from the DB. Called after a write
    // batch so the report reflects the persisted verdicts. An audit failure
    // returns an error envelope (never a silent null that reads as success).
    const runAudit = async (scanId: string, outDir: string, aiDurationMs?: number, allowPartial?: boolean) => {
      try {
        const hasAI = aiDurationMs != null && aiDurationMs >= 0
        const partialFlag = allowPartial ? "--allow-partial" : ""
        const auditResult = hasAI
          ? await withKill(Bun.$`${secguardBin} report --db ${dbPath} --audit --scan-id ${scanId} --output-dir ${outDir} --ai-duration-ms ${aiDurationMs} ${partialFlag}`
            .cwd(workDir)
            .quiet(), 120_000, "secguard report --audit")
          : await withKill(Bun.$`${secguardBin} report --db ${dbPath} --audit --scan-id ${scanId} --output-dir ${outDir} ${partialFlag}`
            .cwd(workDir)
            .quiet(), 120_000, "secguard report --audit")
        return JSON.parse(auditResult.trim())
      } catch (e: any) {
        return cliErrorJSON(e, {})
      }
    }

    if (args.action === "audit") {
      if (!args.scan_id || !outputDir) {
        return JSON.stringify({ status: "error", error: "action=audit requires scan_id AND output_dir" }, null, 2)
      }
      const auditJson = await runAudit(args.scan_id, outputDir, args.ai_duration_ms, args.allow_partial)
      return JSON.stringify(auditJson, null, 2)
    }
    if (args.action === "complete_type") {
      if (!args.vuln_type_arg || !args.scan_id) {
        return JSON.stringify({ status: "error", error: "action=complete_type requires vuln_type_arg AND scan_id" }, null, 2)
      }
      try {
        const out = await withKill(Bun.$`${secguardBin} report --db ${dbPath} --complete-type ${args.vuln_type_arg} --scan-id ${args.scan_id}`
          .cwd(workDir)
          .quiet(), 30_000, "secguard report --complete-type")
        return out.trim()
      } catch (e: any) {
        return JSON.stringify(cliErrorJSON(e, {}), null, 2)
      }
    }
    if (args.action === "stats") {
      const scanIdFlag = args.scan_id ? `--scan-id ${args.scan_id}` : ""
      try {
        const out = await withKill(Bun.$`${secguardBin} report --db ${dbPath} --stats ${scanIdFlag}`
          .cwd(workDir)
          .quiet(), 30_000, "secguard report --stats")
        return out.trim()
      } catch (e: any) {
        return JSON.stringify(cliErrorJSON(e, {}), null, 2)
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
        vuln_type: finding.vuln_type || "",
        severity: finding.severity,
        confidence: finding.confidence,
        status: finding.status,
        file: finding.file,
        line: finding.line,
        function: finding.function,
        variable: finding.variable || "",
        summary: finding.summary || "",
        reasoning: finding.reasoning || "",
        exception_check: finding.exception_check || "",
        fix_strategy: finding.fix_strategy || "",
      }))
      fs.writeFileSync(tmpFile, JSON.stringify(inputs))

      const written: { file: string; line: number; id: number; duplicate?: boolean }[] = []
      const errors: string[] = []
      const perFindingWarnings: string[] = []
      let skipped = 0
      let duplicates = 0
      let cliEnvelope: Record<string, unknown> = {}
      try {
        const out = (await withKill(Bun.$`${secguardBin} report --db ${dbPath} --write-json ${tmpFile} --scan-id=${scanId}`
          .cwd(workDir)
          .quiet(), 60_000, "secguard report --write-json")
        ).trim()
        try {
          const parsed = JSON.parse(out)
          cliEnvelope = parsed
          duplicates = typeof parsed.duplicates === "number" ? parsed.duplicates : 0
          for (const w of parsed.written ?? []) {
            if (typeof w.id === "number") {
              written.push({ file: w.file, line: w.line, id: w.id, ...(w.duplicate ? { duplicate: true } : {}) })
            }
          }
          // Per-item failures (unsupported rule_id, empty rule_id, DB error)
          // come back as strings in `errors`; each is one un-written finding.
          for (const e of parsed.errors ?? []) {
            errors.push(String(e))
            skipped++
          }
          if (parsed.warning) perFindingWarnings.push(String(parsed.warning))
        } catch {
          errors.push("unparseable --write-json response")
        }
      } catch (e: any) {
        const partial = cliErrorJSON(e, {})
        if (partial.status === "partial") {
          cliEnvelope = partial
          duplicates = typeof partial.duplicates === "number" ? (partial.duplicates as number) : 0
          for (const w of (partial.written as any[] ?? [])) {
            if (typeof w.id === "number") {
              written.push({ file: w.file, line: w.line, id: w.id, ...(w.duplicate ? { duplicate: true } : {}) })
            }
          }
          for (const err of (partial.errors as any[] ?? [])) errors.push(String(err))
          skipped = typeof partial.failed_count === "number" ? (partial.failed_count as number) : 0
          if (partial.warning) perFindingWarnings.push(String(partial.warning))
        } else {
          errors.push(`batch write failed: ${partial.error}`)
          skipped = args.findings.length
        }
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
        const auditJson = await runAudit(scanId, outputDir, args.ai_duration_ms)
        if (auditJson) {
          auditPath = auditJson.audit_path as string | undefined
          // The audit pass re-syncs findings/ with the database: it reports how
          // many verdict files were written and how many dismissed/unclassified
          // leftovers were swept out of the review surface.
          findingsSynced = auditJson.findings_synced
          if (auditJson.warning) perFindingWarnings.push(String(auditJson.warning))
          if (auditJson.error) perFindingWarnings.push(String(auditJson.error))
        }
      }

      return JSON.stringify(
        {
          status: errors.length === 0 ? "ok" : "partial",
          findings_written: written.length,
          duplicates,
          skipped,
          written,
          audit_path: auditPath,
          findings_synced: findingsSynced,
          errors,
          dismissed_written: cliEnvelope.dismissed_written,
          dismissed_failed: cliEnvelope.dismissed_failed,
          failed_count: cliEnvelope.failed_count,
          failed_details: cliEnvelope.failed_details,
          salvaged: cliEnvelope.salvaged,
          truncated: cliEnvelope.truncated,
          // Non-empty means those verdicts never reached findings/<vuln-type>/:
          // re-issue the write with scan_id + output_dir.
          per_finding_warnings: perFindingWarnings,
        },
        null,
        2
      )
    }

    const scanIdFlag = args.scan_id ? `--scan-id ${args.scan_id}` : ""
    const result = await withKill(Bun.$`${secguardBin} report --db ${dbPath} --list ${scanIdFlag}`
      .cwd(workDir)
      .quiet(), 30_000, "secguard report (read)")
      .catch((e: any) => {
        return JSON.stringify(cliErrorJSON(e, { findings: [] }))
      })

    // Paginate in the wrapper: a whole findings table must never be dumped into
    // the model context. The full JSON goes to a side file; the response is one
    // page plus the cursor and the side-file path for a deliberate deep read.
    try {
      const parsed = JSON.parse(result.trim())
      const all = parsed.findings ?? []
      const limit = args.limit && args.limit > 0 ? Math.floor(args.limit) : 50
      const offset = args.cursor && args.cursor >= 0 ? Math.floor(args.cursor) : 0
      const page = all.slice(offset, offset + limit)
      const nextCursor = offset + limit < all.length ? offset + limit : null
      const tmpDir = path.join(sgreDir, ".tmp")
      if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true })
      const fullPath = path.join(tmpDir, `findings-list-${randomUUID()}.json`)
      fs.writeFileSync(fullPath, JSON.stringify(parsed, null, 2))
      return JSON.stringify({ count: all.length, offset, limit, next_cursor: nextCursor, full_result_file: fullPath, findings: page, message: parsed.message }, null, 2)
    } catch {
      return result.trim()
    }
  },
})
