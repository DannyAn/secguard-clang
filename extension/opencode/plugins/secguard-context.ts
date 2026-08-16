import { type Plugin } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"

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
  }
}
