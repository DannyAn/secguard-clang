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
import secguard_metrics from "./tools/secguard_metrics"

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
  "secguard_metrics",
]

type YamlValue = string | YamlMap
interface YamlMap {
  [key: string]: YamlValue
}

function unquote(value: string): string {
  if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
    return value.slice(1, -1)
  }
  return value
}

// Minimal YAML-subset parser for the frontmatter we author (flat `key: value`
// scalars plus one level of nested maps for `permission` / `permission.bash`).
// OpenCode's native YAML frontmatter uses the same shape, so the file stays
// valid even if the host also parses it.
function parseYaml(text: string): YamlMap {
  const lines: { indent: number; key: string; value: string }[] = []
  for (const raw of text.split(/\r?\n/)) {
    const trimmed = raw.trim()
    if (trimmed === "" || trimmed.startsWith("#")) continue
    const idx = trimmed.indexOf(":")
    if (idx <= 0) continue
    lines.push({
      indent: raw.length - trimmed.length,
      key: unquote(trimmed.slice(0, idx).trim()),
      value: trimmed.slice(idx + 1).trim(),
    })
  }

  const root: YamlMap = {}
  const stack: { indent: number; map: YamlMap }[] = [{ indent: -1, map: root }]
  for (const line of lines) {
    while (stack.length > 1 && stack[stack.length - 1].indent >= line.indent) {
      stack.pop()
    }
    const current = stack[stack.length - 1]
    if (line.value === "") {
      const child: YamlMap = {}
      current.map[line.key] = child
      stack.push({ indent: line.indent, map: child })
    } else {
      current.map[line.key] = unquote(line.value)
    }
  }
  return root
}

function parseFrontmatter(md: string): { data: YamlMap; body: string } {
  const match = md.match(/^---\r?\n([\s\S]*?)\r?\n---\r?\n?/)
  if (!match) return { data: {}, body: md.trim() }
  return { data: parseYaml(match[1]), body: md.slice(match[0].length).trim() }
}

function asString(value: YamlValue | undefined): string | undefined {
  return typeof value === "string" ? value : undefined
}

function asMap(value: YamlValue | undefined): YamlMap | undefined {
  return value !== undefined && typeof value === "object" ? value : undefined
}

function asNumber(value: YamlValue | undefined, field: string): number {
  if (typeof value !== "string" || value.trim() === "") {
    throw new Error(`secguard-clang: agent frontmatter field "${field}" is missing or empty`)
  }
  const n = Number(value)
  if (!Number.isFinite(n)) {
    throw new Error(`secguard-clang: agent frontmatter field "${field}" must be a number, got "${value}"`)
  }
  return n
}

function loadCommands() {
  const commands: Record<string, { template: string; description?: string }> = {}
  const dir = path.join(pluginDir, "commands")
  for (const file of fs.readdirSync(dir)) {
    if (!file.endsWith(".md")) continue
    const name = file.slice(0, -3)
    const { data, body } = parseFrontmatter(fs.readFileSync(path.join(dir, file), "utf8"))
    const description = asString(data["description"])
    commands[`secguard-clang/${name}`] = {
      template: body,
      ...(description ? { description } : {}),
    }
  }
  return commands
}

// agents/security-auditor.md frontmatter is the single source of truth for the
// agent's runtime config (mode / temperature / steps / permission). No value is
// hardcoded here — a missing/invalid numeric field fails loudly at plugin init.
function loadAgent() {
  const file = path.join(pluginDir, "agents", "security-auditor.md")
  const { data, body } = parseFrontmatter(fs.readFileSync(file, "utf8"))
  const mode = asString(data["mode"])
  const permission = asMap(data["permission"])
  if (!mode) throw new Error('secguard-clang: agent frontmatter field "mode" is missing')
  if (!permission) throw new Error('secguard-clang: agent frontmatter field "permission" is missing')
  return {
    mode,
    description: asString(data["description"]) ?? "",
    temperature: asNumber(data["temperature"], "temperature"),
    steps: asNumber(data["steps"], "steps"),
    permission,
    prompt: body,
  }
}

// KEEP IN SYNC with opencode-nga/plugins/secguard-context.ts — the two OpenCode
// hosts share this context-enhancement logic (resolveWorkDir + tool.execute.before
// + file.edited event). Change it in both places.
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
        secguard_metrics,
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
