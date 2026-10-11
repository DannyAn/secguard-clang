import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import { fileURLToPath } from "url"
import { randomUUID } from "crypto"

// withTimeout bounds a subprocess wait so a stuck secguard CLI fails fast.
async function withTimeout<T>(p: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new Error(`${label} timed out after ${ms}ms`)), ms)
  })
  try {
    return await Promise.race([p, timeout])
  } finally {
    if (timer) clearTimeout(timer)
  }
}

function findSecguard(context: { worktree?: string; directory?: string }): string {
  const pluginDir = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
  const os = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux"
  const arch = process.arch === "x64" ? "amd64" : process.arch
  const bundled = path.join(pluginDir, "bin", `secguard-${os}-${arch}${os === "windows" ? ".exe" : ""}`)
  if (fs.existsSync(bundled)) return bundled
  for (const dir of [context.directory, context.worktree, "."]) {
    if (!dir || dir === "/") continue
    const local = path.join(dir, ".opencode/bin/secguard")
    if (fs.existsSync(local)) return local
  }
  return "secguard"
}

export default tool({
  description:
    "Re-review the machine auto-confirmed findings (the pipeline-proved tier the candidate index does NOT show). Two operations: (1) list_auto_confirmed=true returns them for your type as JSON (id / rule_id / file / line / function / variable / reasoning / snippet) so you can apply the skill's false-positive rules; (2) reviews=[...] writes your verdicts back — review_status 'confirmed' (agree) or 'dismissed' (the machine verdict is a false positive → suppressed from result.sarif). Write a verdict for EVERY entry (do NOT omit the ones you agree with): the orchestrator verifies the re-review by checking that a later list_auto_confirmed returns count 0, which only holds when every entry got a review_status. This is the agent-native second-round review (no external AI provider).",
  args: {
    scan_id: tool.schema
      .string()
      .optional()
      .describe("Scan ID. Defaults to the latest scan when omitted."),
    type: tool.schema
      .string()
      .optional()
      .describe("Vulnerability type (kebab-case, e.g. memory-leak). Scopes list_auto_confirmed to one type's CWE set — pass your assigned type."),
    limit: tool.schema
      .number()
      .optional()
      .describe("When list_auto_confirmed is true, cap the batch size (e.g. 50) so a large set is pulled in pages instead of overflowing context. Re-list until the returned count is 0."),
    list_auto_confirmed: tool.schema
      .boolean()
      .optional()
      .describe("When true, list the machine auto-confirmed findings for re-review."),
    reviews: tool.schema
      .array(
        tool.schema.object({
          id: tool.schema.number().describe("Finding id from list_auto_confirmed"),
          review_status: tool.schema
            .string()
            .describe("confirmed (agree) | dismissed (machine false positive)"),
          review_reasoning: tool.schema
            .string()
            .describe("Cited evidence: the snippet/source line + why it is safe / a false positive"),
        })
      )
      .optional()
      .describe("Re-review verdicts to write back in one batch."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const sgreDir = path.join(workDir, ".codeagent", "secguard-clang", ".sgre")
    if (!fs.existsSync(sgreDir)) fs.mkdirSync(sgreDir, { recursive: true })
    const dbPath = path.join(sgreDir, "sgre.db")

    // Write path: reviews -> --review-json (one batch subprocess).
    if (args.reviews && args.reviews.length > 0) {
      const tmpDir = path.join(sgreDir, ".tmp")
      if (!fs.existsSync(tmpDir)) fs.mkdirSync(tmpDir, { recursive: true })
      const tmpFile = path.join(tmpDir, `review-${randomUUID()}.json`)
      fs.writeFileSync(
        tmpFile,
        JSON.stringify(
          args.reviews.map((r) => ({
            id: r.id,
            review_status: r.review_status,
            review_reasoning: r.review_reasoning || "",
          }))
        )
      )
      try {
        const out = (
          await withTimeout(
            Bun.$`${secguardBin} report --db ${dbPath} --review-json ${tmpFile}`
              .cwd(workDir)
              .quiet()
              .text(),
            60_000,
            "secguard report --review-json"
          )
        ).trim()
        try {
          return JSON.stringify(JSON.parse(out), null, 2)
        } catch {
          return JSON.stringify({ status: "error", error: "unparseable --review-json response", raw: out })
        }
      } catch (e: any) {
        const msg = e?.stderr?.toString()?.trim() || e?.message || String(e)
        return JSON.stringify({ status: "error", error: `review write failed: ${msg}` })
      } finally {
        try { fs.unlinkSync(tmpFile) } catch {}
      }
    }

    // List path (also the default when neither arg is set): --list-auto-confirmed.
    const typeArg = args.type ? ` --type ${args.type}` : ""
    const scanArg = args.scan_id ? ` --scan-id ${args.scan_id}` : ""
    const limitArg = args.limit && args.limit > 0 ? ` --limit ${args.limit}` : ""
    try {
      const out = (
        await withTimeout(
          Bun.$`${secguardBin} report --db ${dbPath} --list-auto-confirmed${scanArg}${typeArg}${limitArg}`
            .cwd(workDir)
            .quiet()
            .text(),
          30_000,
          "secguard report --list-auto-confirmed"
        )
      ).trim()
      try {
        return JSON.stringify(JSON.parse(out), null, 2)
      } catch {
        return JSON.stringify({ findings: [], error: "unparseable list response", raw: out })
      }
    } catch (e: any) {
      const msg = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ findings: [], error: msg })
    }
  },
})
