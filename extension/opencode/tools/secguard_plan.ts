import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"

const VULN_TYPES = [
  "null-deref",
  "buffer-overflow",
  "memory-leak",
  "injection",
  "resource-leak",
  "uninit",
  "use-after-free",
  "double-free",
  "format-string",
  "integer-overflow",
  "race-condition",
  "hardcoded-secret",
  "deadlock",
  "crypto-misuse",
] as const

const VULN_TYPES_STR = VULN_TYPES.join(", ")

function findSecguard(context: { worktree?: string, directory?: string }): string {
  let dir = context.worktree || context.directory || "."
  if (dir === "/") dir = "."
  const bundled = path.join(dir, ".opencode/bin/secguard")
  if (fs.existsSync(bundled)) return bundled
  return "secguard"
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

function printPlanSummary(w: { write(s: string): boolean }, goJson: any): void {
  const vulnType = goJson?.vulnerability_type ?? "N/A"
  const cwe = CWE_MAP[vulnType] ?? "CWE-Other"
  const seedCount = goJson?.summary?.seed_count ?? 0
  const finalCount = goJson?.summary?.final_count ?? 0
  const filters = goJson?.summary?.filters ?? []
  const candidates = goJson?.candidates ?? []

  let out = "## SecGuard Plan Summary\n\n"
  out += "| Field | Value |\n"
  out += "|-------|-------|\n"
  out += `| Vulnerability Type | ${vulnType} |\n`
  out += `| CWE | ${cwe} |\n`
  out += `| Seed Count | ${seedCount} |\n`
  out += `| Final Count | ${finalCount} |\n\n`

  if (filters.length > 0) {
    out += "### Filter Chain\n\n"
    out += "| Filter | Input | Output |\n"
    out += "|--------|-------|--------|\n"
    for (const f of filters) {
      out += `| ${f?.name ?? "?"} | ${f?.input_count ?? 0} | ${f?.output_count ?? 0} |\n`
    }
    out += "\n"
  }

  out += "### Candidates\n\n"
  if (candidates.length === 0) {
    out += "No candidates after convergence.\n"
  } else {
    out += "| # | Function | File:Line | Variable | Suspicion |\n"
    out += "|---|----------|-----------|----------|-----------|\n"
    for (let i = 0; i < candidates.length; i++) {
      const c = candidates[i]
      const fn = c?.target?.function ?? "?"
      const file = c?.target?.file ?? "?"
      const line = c?.target?.line ?? 0
      const variable = c?.target?.variable ?? ""
      const suspicion = c?.suspicion_level ?? ""
      out += `| ${i + 1} | ${fn} | ${file}:${line} | ${variable} | ${suspicion} |\n`
    }
  }

  w.write(out)
}

export default tool({
  description:
    "Run the SecGuard convergence pipeline for a specific vulnerability type. Returns <=30 converged evidence candidates as JSON. The pipeline applies 4 filters: nullable source, call reachability, data flow, guard existence.",
  args: {
    vuln_type: tool.schema
      .string()
      .describe(
        `Vulnerability type: ${VULN_TYPES_STR}`
      ),
    max_candidates: tool.schema
      .number()
      .optional()
      .describe("Maximum candidates to retain after convergence (default: 30). Increase for codebases with many true positives in one vulnerability type."),
  },
  async execute(args, context) {
    if (!VULN_TYPES.includes(args.vuln_type as any)) {
      return JSON.stringify({
        error: `Invalid vulnerability type '${args.vuln_type}'. Valid types: ${VULN_TYPES_STR}. Example: secguard_plan vuln_type=buffer-overflow`,
        vuln_type: args.vuln_type,
      }, null, 2)
    }

    let workDir = context.worktree || context.directory || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = path.join(workDir, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")

    try {
      let cmd
      if (args.max_candidates && args.max_candidates > 0) {
        cmd = Bun.$`${secguardBin} plan --db ${dbPath} --max-candidates ${args.max_candidates} ${args.vuln_type}`
      } else {
        cmd = Bun.$`${secguardBin} plan --db ${dbPath} ${args.vuln_type}`
      }
      const result = await cmd.cwd(workDir).quiet().text()

      try {
        const goJson = JSON.parse(result.trim())
        printPlanSummary(process.stderr, goJson)
      } catch {
      }

      return result.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: err, vuln_type: args.vuln_type, db_path: dbPath }, null, 2)
    }
  },
})
