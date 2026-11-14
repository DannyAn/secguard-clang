import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import { findSecguard } from "../findSecguard"
import { randomUUID } from "crypto"

// withKill bounds a subprocess wait AND terminates the child on expiry: a bare
// Promise.race rejected the caller while the CLI kept running (and could still
// commit), splitting "caller saw failure" from "DB says success".
async function withKill(proc: { text(): Promise<string>, kill(): void }, ms: number, label: string): Promise<string> {
  const timer = setTimeout(() => { try { proc.kill() } catch { /* already exited */ } }, ms)
  try {
    return await proc.text()
  } catch (e: any) {
    throw new Error(`${label} outcome_unknown after ${ms}ms (subprocess killed; query the DB before retrying): ${e?.message || e}`)
  } finally {
    clearTimeout(timer)
  }
}


export default tool({
  description:
    "Write re-review verdicts for the machine auto-confirmed findings (Step 5.5 of command-instructions.md): reviews=[...] maps to `report --review-json` in ONE idempotent batch. review_status 'dismissed' suppresses a machine false positive from result.sarif; 'confirmed' agrees. There is NO completeness gate and NO per-candidate loop — Step 5.5 is bounded and optional. With no reviews, the tool lists the unreviewed machine findings (status='auto-confirmed' with review_status NULL, i.e. exactly the rows Step 5.5 must judge) via `report --list-auto-confirmed`.",
  args: {
    scan_id: tool.schema
      .string()
      .optional()
      .describe("Scan ID. Defaults to the latest scan when omitted."),
    type: tool.schema
      .string()
      .optional()
      .describe("Vulnerability type (kebab-case, e.g. memory-leak) for the list operation."),
    limit: tool.schema
      .number()
      .optional()
      .describe("Paging cap for the list operation."),
    list_auto_confirmed: tool.schema
      .boolean()
      .optional()
      .describe("List the unreviewed machine findings (status='auto-confirmed', review_status NULL) instead of writing verdicts."),
    reviews: tool.schema
      .array(
        tool.schema.object({
          id: tool.schema.number().describe("Finding id from the Step 5.5 listing (secguard_db raw SQL: SELECT id ... WHERE status='auto-confirmed')"),
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
    const dbPath = (args as any).db_path || path.join(sgreDir, "sgre.db")

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
          await withKill(
            Bun.$`${secguardBin} report --db ${dbPath} --review-json ${tmpFile}`
              .cwd(workDir)
              .quiet(),
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
    // Optional flags are pushed as SEPARATE argv elements (array interpolation).
    // A flag joined into one string with a leading space is passed by Bun.$ as a
    // SINGLE argv element (no word-splitting), which the CLI's flag parser does
    // not match — the filter is silently dropped and the subagent gets the whole
    // scan's list instead of its own type's page.
    const listCmd = [secguardBin, "report", "--db", dbPath, "--list-auto-confirmed"]
    if (args.scan_id) listCmd.push("--scan-id", args.scan_id)
    if (args.type) listCmd.push("--type", args.type)
    if (args.limit && args.limit > 0) listCmd.push("--limit", String(args.limit))
    try {
      const out = (
        await withKill(
          Bun.$`${listCmd}`
            .cwd(workDir)
            .quiet(),
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
