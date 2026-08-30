import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import { fileURLToPath } from "url"

import secguard_scan from "./tools/secguard_scan"
import secguard_index from "./tools/secguard_index"
import secguard_plan from "./tools/secguard_plan"
import secguard_report from "./tools/secguard_report"
import secguard_status from "./tools/secguard_status"
import secguard_db from "./tools/secguard_db"
import secguard_schema from "./tools/secguard_schema"
import secguard_types from "./tools/secguard_types"

const pluginDir = path.dirname(fileURLToPath(import.meta.url))

const SECGUARD_TOOLS = [
  "secguard_scan",
  "secguard_index",
  "secguard_plan",
  "secguard_report",
  "secguard_status",
  "secguard_db",
  "secguard_schema",
  "secguard_types",
]

function parseFrontmatter(md: string): { data: Record<string, string>; body: string } {
  const match = md.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)
  if (!match) return { data: {}, body: md.trim() }
  const data: Record<string, string> = {}
  for (const line of match[1].split(/\r?\n/)) {
    if (/^\s/.test(line)) continue
    const idx = line.indexOf(":")
    if (idx <= 0) continue
    const key = line.slice(0, idx).trim()
    let value = line.slice(idx + 1).trim()
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
      value = value.slice(1, -1)
    }
    data[key] = value
  }
  return { data, body: md.slice(match[0].length).trim() }
}

function loadCommands() {
  const commands: Record<string, { template: string; description?: string }> = {}
  const dir = path.join(pluginDir, "commands")
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith(".md")) continue
    const name = file.slice(0, -3)
    const { data, body } = parseFrontmatter(fs.readFileSync(path.join(dir, file), "utf8"))
    commands[`secguard-clang/${name}`] = {
      template: body,
      ...(data.description ? { description: data.description } : {}),
    }
  }
  return commands
}

function loadAgent() {
  const file = path.join(pluginDir, "agents", "security-auditor.md")
  const { data, body } = parseFrontmatter(fs.readFileSync(file, "utf8"))
  return {
    mode: "all",
    description: data.description,
    temperature: 0.1,
    steps: 200,
    permission: {
      edit: "allow",
      bash: { "*": "deny", "secguard*": "allow", "echo*": "allow" },
      read: "allow",
      grep: "allow",
      glob: "allow",
      external_directory: "allow",
      skill: "allow",
    },
    prompt: body,
  }
}

function resolveWorkDir(context: { worktree?: string; directory?: string }): string {
  let dir = context.directory || context.worktree || "."
  if (dir === "/") dir = "."
  return dir
}

export default {
  id: "secguard-clang",
  server: async ({ client, directory, worktree }: any) => {
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
      config: async (cfg: any) => {
        cfg.command = cfg.command ?? {}
        Object.assign(cfg.command, loadCommands())

        cfg.agent = cfg.agent ?? {}
        cfg.agent["security-auditor"] = loadAgent()

        cfg.skills = cfg.skills ?? {}
        const skillsPath = path.join(pluginDir, "skills")
        cfg.skills.paths = [...(cfg.skills.paths ?? []), skillsPath]

        cfg.permission = cfg.permission ?? {}
        cfg.permission.external_directory = "allow"
        for (const name of SECGUARD_TOOLS) cfg.permission[name] = "allow"
      },
      "tool.execute.before": async (input: any, output: any) => {
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
      event: async ({ event }: any) => {
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
  },
}
