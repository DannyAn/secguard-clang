import { type Plugin, tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"

const ALL_VULN_TYPES = [
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
]

function resolveWorkDir(context: { worktree?: string, directory?: string }): string {
  let dir = context.worktree || context.directory || "."
  if (dir === "/") dir = "."
  return dir
}

function findSecguard(dir: string): string {
  const bundled = path.join(dir, ".opencode/bin/secguard")
  if (fs.existsSync(bundled)) return bundled
  return "secguard"
}

export const SecGuardContextPlugin: Plugin = async ({
  project,
  client,
  $,
  directory,
  worktree,
}) => {
  return {
    "tool.execute.before": async (input, output) => {
      if (input.tool?.startsWith("secguard_")) {
        const dir = resolveWorkDir({ worktree, directory })
        if (input.tool === "secguard_scan" || input.tool === "secguard_index") {
          if (!output.args) output.args = {}
          if (!output.args.path) {
            output.args.path = dir
          }
        }
      }
    },

    event: async ({ event }) => {
      if (event.type === "file.edited") {
        const dir = resolveWorkDir({ worktree, directory })
        const dbPath = path.join(dir, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
        if (fs.existsSync(dbPath)) {
          try {
            await client.app.log(
              "SecGuard index may be stale — source file was edited. Re-run /secguard to refresh."
            )
          } catch {}
        }
      }
    },

    tool: {
      secguard_quick_scan: tool({
        description:
          "Quick scan: check if sgre.db exists and is fresh, run scan only if needed. Returns evidence packages for all 14 or a filtered subset of vulnerability types.",
        args: {
          force: tool.schema
            .boolean()
            .optional()
            .describe("Force re-index even if DB exists"),
          vuln_types: tool.schema
            .string()
            .optional()
            .describe(
              `Optional filter: comma-separated vulnerability types. Default: all 14 types. Valid types: ${ALL_VULN_TYPES.join(", ")}`
            ),
        },
        async execute(args, context) {
          const dir = resolveWorkDir(context)
          const secguardBin = findSecguard(dir)
          const dbPath = path.join(dir, ".codeagent", "zhuque-secguard", ".sgre", "sgre.db")
          const exists = fs.existsSync(dbPath)

          let selectedTypes: string[] = [...ALL_VULN_TYPES]
          if (args.vuln_types) {
            const requested = args.vuln_types
              .split(",")
              .map(t => t.trim())
              .filter(t => t.length > 0)
            const invalid = requested.filter(t => !ALL_VULN_TYPES.includes(t as any))
            if (invalid.length > 0) {
              return JSON.stringify({
                error: `Invalid vulnerability type(s): ${invalid.join(", ")}. Valid types: ${ALL_VULN_TYPES.join(", ")}`,
              }, null, 2)
            }
            selectedTypes = [...new Set(requested)]
          }

          if (exists && !args.force) {
            try {
              const status = await $`${secguardBin} status --db ${dbPath}`
                .cwd(dir)
                .quiet()
                .text()
              const statusJson = JSON.parse(status.trim())
              if (statusJson.stale === false) {
                const packages = []
                for (const vt of selectedTypes) {
                  const planResult = await $`${secguardBin} plan --db ${dbPath} ${vt}`
                    .cwd(dir)
                    .quiet()
                    .text()
                    .catch(() => "{}")
                  packages.push({
                    vulnerability_type: vt,
                    ...JSON.parse(planResult.trim() || "{}"),
                  })
                }
                return JSON.stringify(
                  { evidence_packages: packages, cached: true },
                  null,
                  2
                )
              }
            } catch {}
          }

          const scanResult = await $`${secguardBin} scan --db ${dbPath} ${dir}`
            .cwd(dir)
            .quiet()
            .text()
            .catch(() => '{"evidence_packages":[]}')

          return scanResult.trim()
        },
      }),
    },
  }
}
