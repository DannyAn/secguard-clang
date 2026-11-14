import path from "path"
import fs from "fs"
import { fileURLToPath } from "url"

// findSecguard resolves the secguard binary the OpenCode tools must execute.
// It returns ONLY the plugin's own bundled binary (Market install) or a PATH
// `secguard` — never a repository-local `.opencode/bin/secguard`. A scanned
// untrusted repository could commit an executable at that path, and running it
// would turn a scan/status query into arbitrary code execution (issue #275 P0-2).
export function findSecguard(_context: { worktree?: string, directory?: string }): string {
  const pluginDir = path.dirname(fileURLToPath(import.meta.url))
  const os = process.platform === "win32" ? "windows" : process.platform === "darwin" ? "darwin" : "linux"
  const arch = process.arch === "x64" ? "amd64" : process.arch
  const bundled = path.join(pluginDir, "bin", `secguard-${os}-${arch}${os === "windows" ? ".exe" : ""}`)
  if (fs.existsSync(bundled)) return bundled
  return "secguard"
}
