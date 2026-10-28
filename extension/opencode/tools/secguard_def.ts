import { tool } from "@opencode-ai/plugin"
import path from "path"
import fs from "fs"
import { fileURLToPath } from "url"

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
    "Resolve a C symbol definition from the SecGuard index — use this INSTEAD of a repo-wide grep when a candidate's verdict needs a callee/macro/type contract. Functions and declarations come from the semantic graph (O(1) lookup); #define bodies come from project headers; the definition body is returned inline. Batch related symbols in one call (e.g. ['ase_sa_str_connect','sa_print_ipv4_string']). found:false means the symbol is external/unindexed — judge from API knowledge, do not grep for it.",
  args: {
    symbol: tool.schema
      .string()
      .optional()
      .describe("A single C symbol to resolve (e.g. 'ase_sa_str_connect'). Use this or symbols."),
    symbols: tool.schema
      .array(tool.schema.string())
      .optional()
      .describe("Batch of symbols to resolve in one call (max 16). Use for a callee pair / macro pair."),
    kind: tool.schema
      .string()
      .optional()
      .describe("Restrict the lookup: auto (default) | function | declaration | macro | type | variable"),
    in_file: tool.schema
      .string()
      .optional()
      .describe("Also scan this file for a #define (a macro local to the candidate's own .c). Relative paths resolve against --root."),
    root: tool.schema
      .string()
      .optional()
      .describe("Project root for the header scan; omit to derive it from the indexed files (common root / nearest include dir)."),
    db_path: tool.schema
      .string()
      .optional()
      .describe("Path to sgre.db; omit for <workdir>/.codeagent/secguard-clang/.sgre/sgre.db. Pass the scan's DB when your working directory is not the project root."),
  },
  async execute(args, context) {
    let workDir = context.directory || context.worktree || "."
    if (workDir === "/") workDir = "."
    const secguardBin = findSecguard(context)
    const dbPath = args.db_path || path.join(workDir, ".codeagent", "secguard-clang", ".sgre", "sgre.db")

    const names = args.symbols?.length ? args.symbols : args.symbol ? [args.symbol] : []
    if (names.length === 0) {
      return JSON.stringify({ error: "provide `symbol` or a non-empty `symbols` array" }, null, 2)
    }

    // Optional flags are pushed as SEPARATE argv elements (array interpolation).
    // A flag joined into one string with a leading space is passed by Bun.$ as a
    // SINGLE argv element and the CLI's flag parser would silently drop it.
    const cmd = [secguardBin, "def", ...names, "--db", dbPath]
    if (args.kind) cmd.push("--kind", args.kind)
    if (args.in_file) cmd.push("--in", args.in_file)
    if (args.root) cmd.push("--root", args.root)

    try {
      const out = await Bun.$`${cmd}`.cwd(workDir).quiet().text()
      return out.trim()
    } catch (e: any) {
      const err = e?.stderr?.toString()?.trim() || e?.message || String(e)
      return JSON.stringify({ error: err, db_path: dbPath }, null, 2)
    }
  },
})
