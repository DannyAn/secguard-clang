import { type Plugin } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"

// The 8 secguard_* tools live in tools/*.ts and are registered here via the
// plugin's `tool` hook — same as opencode/index.ts's `server.tool`. Without
// this, the fork's extensions/ loader never registers the tools (the tools/
// directory alone is not auto-discovered).
import secguard_scan from "../tools/secguard_scan"
import secguard_index from "../tools/secguard_index"
import secguard_plan from "../tools/secguard_plan"
import secguard_report from "../tools/secguard_report"
import secguard_status from "../tools/secguard_status"
import secguard_db from "../tools/secguard_db"
import secguard_schema from "../tools/secguard_schema"
import secguard_types from "../tools/secguard_types"

// KEEP IN SYNC with opencode/index.ts — the two OpenCode hosts share this
// context-enhancement logic (resolveWorkDir + tool.execute.before + file.edited
// event). Change it in both places.
function resolveWorkDir(context: { worktree?: string, directory?: string }): string {
  let dir = context.directory || context.worktree || "."
  if (dir === "/") dir = "."
  return dir
}

export const SecGuardContextPlugin: Plugin = async ({
  client,
  directory,
  worktree,
}) => {
  return {
    tool: {
      secguard_scan,
      secguard_index,
      secguard_plan,
      secguard_report,
      secguard_status,
      secguard_db,
      secguard_schema,
      secguard_types,
    },

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
        const dbPath = path.join(dir, ".codeagent", "secguard-clang", ".sgre", "sgre.db")
        if (fs.existsSync(dbPath)) {
          try {
            await client.app.log(
              "SecGuard index may be stale — source file was edited. Re-run /secguard to refresh."
            )
          } catch {}
        }
      }
    },
  }
}
