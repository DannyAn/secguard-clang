#!/bin/bash
# lib.sh — SecGuard 共享函数库
#
# 结构：
#   1. 可注入区（@@SG_INJECT_START@@ ~ @@SG_INJECT_END@@）：sg_ 前缀函数，
#      自包含，不 source 外部文件。打包时由 extract_inject_block 提取，
#      inject_into 注入到 zip 内 install.sh / uninstall.sh。
#   2. 构建侧专用函数：仅在源码树中加载时使用，不打入 zip。
#
# 设计原则：构建侧共享 + 安装侧自包含（NFR-MAINT-01/01a）

# ──────────────────────────────────────────────────────────────
# 可注入区开始：以下函数会被内联注入到发行包脚本中
# ──────────────────────────────────────────────────────────────
# @@SG_INJECT_START@@

# SecGuard 权限项（7 项），供 merge/remove/check 共用
sg_required_permissions() {
    cat <<'SG_PERMS'
Bash(secguard scan *)
Bash(secguard index *)
Bash(secguard plan *)
Bash(secguard report *)
Bash(secguard status *)
Bash(secguard query *)
Bash(secguard db *)
SG_PERMS
}

# 模板展开：将 {{include shared/<name>}} 替换为 shared_dir/<name> 内容
# 用法：sg_expand_includes <input_file> <output_file> <shared_dir>
sg_expand_includes() {
    local input_file="$1"
    local output_file="$2"
    local shared_dir="$3"
    cp "$input_file" "$output_file"
    python3 -c "
import os, re
out = '''$output_file'''
sdir = '''$shared_dir'''
with open(out, 'r') as f:
    content = f.read()
def repl(m):
    rel = m.group(1)  # e.g. shared/agent-body.md
    parts = rel.split('/', 1)
    if len(parts) != 2:
        return m.group(0)
    name = parts[1]
    path = os.path.join(sdir, name)
    try:
        with open(path, 'r') as f:
            return f.read()
    except FileNotFoundError:
        return m.group(0)
content = re.sub(r'\{\{include\s+(shared/[^\s}]+)\}\}', repl, content)
with open(out, 'w') as f:
    f.write(content)
"
}

# 检测操作系统：Darwin→darwin, Linux→linux, MSYS/MinGW/Cygwin→windows
sg_detect_os() {
    case "$(uname -s)" in
        Darwin) echo "darwin" ;;
        Linux)  echo "linux" ;;
        MINGW*|MSYS*|CYGWIN*) echo "windows" ;;
        *)      uname -s | tr '[:upper:]' '[:lower:]' ;;
    esac
}

# 检测架构：x86_64→amd64, aarch64/arm64→arm64
sg_detect_arch() {
    case "$(uname -m)" in
        x86_64)  echo "amd64" ;;
        aarch64) echo "arm64" ;;
        arm64)   echo "arm64" ;;
        *)       uname -m ;;
    esac
}

# 选择匹配平台的二进制
# 用法：sg_select_binary <pkg_dir> <os> <arch>
# 成功 stdout 输出路径返回 0；失败 stderr 列出候选返回 1
sg_select_binary() {
    local pkg_dir="$1"
    local os="$2"
    local arch="$3"
    local exts=("")
    # Windows 二进制带 .exe 后缀，优先匹配 .exe 再回退无后缀
    [ "$os" = "windows" ] && exts=(".exe" "")
    # 仅检查文件存在，不检查 -x 执行位：zip 解压后源二进制权限可能为 644，
    # install_binary() 复制到目标目录后会 chmod +x，源文件无需可执行权限。
    local ext candidate
    for ext in "${exts[@]}"; do
        candidate="$pkg_dir/secguard-${os}-${arch}${ext}"
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
        # 也尝试 bin/ 子目录（ClaudeCode 专用包）
        candidate="$pkg_dir/bin/secguard-${os}-${arch}${ext}"
        if [ -f "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    echo "ERROR: No binary for ${os}/${arch} in $pkg_dir" >&2
    echo "Available binaries:" >&2
    ls -1 "$pkg_dir"/secguard-* "$pkg_dir"/bin/secguard-* 2>/dev/null >&2 || echo "  (none)" >&2
    return 1
}

# 写安装清单 manifest
# 用法：sg_write_install_manifest <manifest_path> <version> <target> <bin_path> <files_csv>
sg_write_install_manifest() {
    local manifest_path="$1"
    local version="$2"
    local target="$3"
    local bin_path="$4"
    local files_csv="$5"
    python3 -c "
import json, datetime
path = '''$manifest_path'''
version = '''$version'''
target = '''$target'''
bin_path = '''$bin_path'''
files_csv = '''$files_csv'''
files = [f for f in files_csv.split(',') if f]
manifest = {
    'version': version,
    'install_date': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
    'target': target,
    'bin_path': bin_path,
    'files': files,
}
with open(path, 'w') as f:
    json.dump(manifest, f, indent=2)
    f.write('\n')
"
}

# 读安装清单 manifest
# 用法：sg_read_install_manifest <manifest_path>
# 成功 stdout 输出 JSON 返回 0；不存在/损坏返回非 0
sg_read_install_manifest() {
    local manifest_path="$1"
    [ -f "$manifest_path" ] || return 1
    python3 -c "
import json, sys
path = '''$manifest_path'''
try:
    with open(path, 'r') as f:
        data = json.load(f)
    print(json.dumps(data))
except Exception as e:
    print(f'ERROR reading manifest: {e}', file=sys.stderr)
    sys.exit(1)
"
}

# 合并 ClaudeCode 权限（幂等，保留 deny 与其它项）
# 用法：sg_merge_permissions <settings_path>
sg_merge_permissions() {
    local settings_path="$1"
    python3 -c "
import json, os
path = '''$settings_path'''
required = [
    'Bash(secguard scan *)',
    'Bash(secguard index *)',
    'Bash(secguard plan *)',
    'Bash(secguard report *)',
    'Bash(secguard status *)',
    'Bash(secguard query *)',
    'Bash(secguard db *)',
]
try:
    with open(path, 'r') as f:
        settings = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    settings = {}
if 'permissions' not in settings:
    settings['permissions'] = {}
if 'allow' not in settings['permissions']:
    settings['permissions']['allow'] = []
if 'deny' not in settings['permissions']:
    settings['permissions']['deny'] = []
existing = set(settings['permissions']['allow'])
added = []
for perm in required:
    if perm not in existing:
        settings['permissions']['allow'].append(perm)
        existing.add(perm)
        added.append(perm)
os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
with open(path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
if added:
    print(f'  Added {len(added)} permission(s): {added}')
else:
    print('  All permissions already present — no changes needed')
"
}

# 移除 ClaudeCode 权限（幂等）
# 用法：sg_remove_permissions <settings_path>
sg_remove_permissions() {
    local settings_path="$1"
    [ -f "$settings_path" ] || return 0
    python3 -c "
import json
path = '''$settings_path'''
required = [
    'Bash(secguard scan *)',
    'Bash(secguard index *)',
    'Bash(secguard plan *)',
    'Bash(secguard report *)',
    'Bash(secguard status *)',
    'Bash(secguard query *)',
    'Bash(secguard db *)',
]
try:
    with open(path, 'r') as f:
        settings = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    return
if 'permissions' not in settings or 'allow' not in settings['permissions']:
    return
before = len(settings['permissions']['allow'])
settings['permissions']['allow'] = [
    p for p in settings['permissions']['allow'] if p not in required
]
removed = before - len(settings['permissions']['allow'])
with open(path, 'w') as f:
    json.dump(settings, f, indent=2)
    f.write('\n')
if removed:
    print(f'  Removed {removed} secguard permission(s)')
"
}

# 检测权限是否已合并
# 用法：sg_check_permissions_merged <settings_path>
# 全在返回 0，缺失返回非 0
sg_check_permissions_merged() {
    local settings_path="$1"
    [ -f "$settings_path" ] || return 1
    python3 -c "
import json, sys
path = '''$settings_path'''
required = [
    'Bash(secguard scan *)',
    'Bash(secguard index *)',
    'Bash(secguard plan *)',
    'Bash(secguard report *)',
    'Bash(secguard status *)',
    'Bash(secguard query *)',
    'Bash(secguard db *)',
]
try:
    with open(path, 'r') as f:
        settings = json.load(f)
except (FileNotFoundError, json.JSONDecodeError):
    sys.exit(1)
allow = set(settings.get('permissions', {}).get('allow', []))
missing = [p for p in required if p not in allow]
if missing:
    sys.exit(1)
"
}

# 交互确认
# 用法：sg_confirm_action <prompt>
# 非 tty 自动返回 0；tty 时 y/yes 返回 0
sg_confirm_action() {
    local prompt="$1"
    if [ ! -t 0 ] && [ ! -t 1 ]; then
        return 0
    fi
    printf '%s [y/N]: ' "$prompt" >&2
    local reply
    read -r reply || return 1
    case "$reply" in
        y|Y|yes|YES|Yes) return 0 ;;
        *) return 1 ;;
    esac
}

# 核心卸载逻辑
# 用法：sg_uninstall_platform <platform> <prefix> <bin_dir> <manifest_path> <yes>
# platform: opencode | claude-code | all
sg_uninstall_platform() {
    local platform="$1"
    local prefix="$2"
    local bin_dir="$3"
    local manifest_path="$4"
    local yes="${5:-false}"
    local oc_prefix cc_prefix
    oc_prefix="${OC_PREFIX:-$HOME/.config/opencode}"
    cc_prefix="${CC_PREFIX:-$HOME/.claude}"

    local to_delete=()
    local manifest_json

    if [ -f "$manifest_path" ]; then
        manifest_json=$(sg_read_install_manifest "$manifest_path" 2>/dev/null) || manifest_json=""
    fi

    if [ -n "$manifest_json" ]; then
        # 从 manifest 提取文件列表并按平台过滤
        local files
        files=$(python3 -c "
import json, sys
m = json.loads('''$manifest_json''')
platform = '''$platform'''
for f in m.get('files', []):
    if platform == 'all':
        print(f)
    elif platform == 'opencode' and ('opencode' in f or 'extensions' in f):
        print(f)
    elif platform == 'claude-code' and ('claude' in f or '.claude' in f or 'skills/secguard-clang' in f):
        print(f)
# 二进制
bin_path = m.get('bin_path', '')
if bin_path and (platform == 'all' or (platform == 'opencode' and 'opencode' not in bin_path and 'claude' not in bin_path) or platform == 'claude-code'):
    if platform == 'all' or bin_path not in [f for f in m.get('files', [])]:
        pass  # bin handled separately
")
        while IFS= read -r f; do
            [ -n "$f" ] && to_delete+=("$f")
        done <<< "$files"
        # 二进制
        local bin_in_manifest
        bin_in_manifest=$(python3 -c "
import json
m = json.loads('''$manifest_json''')
print(m.get('bin_path', '') or '')
")
        if [ -n "$bin_in_manifest" ] && [ "$platform" = "all" ]; then
            to_delete+=("$bin_in_manifest")
        fi
    else
        # manifest 缺失，启发式清理（基础版）
        echo "  WARNING: manifest not found at $manifest_path — heuristic cleanup" >&2
        if [ "$platform" = "all" ] || [ "$platform" = "opencode" ]; then
            to_delete+=("$oc_prefix/extensions/secguard-clang")
        fi
        if [ "$platform" = "all" ] || [ "$platform" = "claude-code" ]; then
            to_delete+=("$cc_prefix/skills/secguard-clang")
        fi
        if [ "$platform" = "all" ]; then
            to_delete+=("$bin_dir/secguard")
        fi
    fi

    if [ ${#to_delete[@]} -eq 0 ]; then
        echo "  Nothing to uninstall for platform: $platform"
        return 0
    fi

    # 展示清单并确认
    echo "  The following will be removed:"
    for item in "${to_delete[@]}"; do
        echo "    - $item"
    done

    if [ "$yes" != "true" ]; then
        sg_confirm_action "Proceed with uninstall?" || {
            echo "  Uninstall cancelled."
            return 1
        }
    fi

    # 执行删除
    for item in "${to_delete[@]}"; do
        if [ -d "$item" ]; then
            rm -rf "$item"
            echo "  Removed dir: $item"
        elif [ -f "$item" ]; then
            rm -f "$item"
            echo "  Removed file: $item"
        fi
    done

    # ClaudeCode 权限移除
    if [ "$platform" = "all" ] || [ "$platform" = "claude-code" ]; then
        sg_remove_permissions "$cc_prefix/settings.json" 2>/dev/null || true
    fi

    # 清理目录残留：manifest 逐文件删除会留下空目录树，且平台过滤会漏掉
    # 全局 command（不在 extensions/ 下），这里对专属目录/文件做兜底清理。
    if [ "$platform" = "all" ] || [ "$platform" = "opencode" ]; then
        rm -rf "$oc_prefix/extensions/secguard-clang" 2>/dev/null || true
        rm -f "$oc_prefix/commands/secguard.md" 2>/dev/null || true
        rmdir "$oc_prefix/extensions" 2>/dev/null || true
        rmdir "$oc_prefix/commands" 2>/dev/null || true
    fi
    if [ "$platform" = "all" ] || [ "$platform" = "claude-code" ]; then
        rm -rf "$cc_prefix/skills/secguard-clang" 2>/dev/null || true
        rm -f "$cc_prefix/commands/secguard.md" 2>/dev/null || true
        rmdir "$cc_prefix/skills" 2>/dev/null || true
        rmdir "$cc_prefix/commands" 2>/dev/null || true
    fi

    # 若 manifest 中所有文件已删，删除 manifest
    if [ -f "$manifest_path" ]; then
        rm -f "$manifest_path" 2>/dev/null || true
    fi

    echo "  Uninstall complete for platform: $platform"
    return 0
}

# 核心验证逻辑
# 用法：sg_verify_platform <platform> <prefix> <bin_dir> <pkg_version>
# 全通过返回 0，否则返回 1
sg_verify_platform() {
    local platform="$1"
    local prefix="$2"
    local bin_dir="$3"
    local pkg_version="$4"
    local oc_prefix cc_prefix
    oc_prefix="${OC_PREFIX:-$HOME/.config/opencode}"
    cc_prefix="${CC_PREFIX:-$HOME/.claude}"
    local pass=0
    local fail=0

    sg_check() {
        if [ "$1" = "ok" ]; then
            echo "  ✓ $2"
            pass=$((pass + 1))
        else
            echo "  ✗ $2"
            fail=$((fail + 1))
        fi
    }

    echo "Verifying installation (platform: $platform, version: $pkg_version)"
    echo "─────────────────────────────────────────────────────────"

    # 二进制检查（Windows 用 .exe 后缀）
    local bin="$bin_dir/secguard"
    [ -f "$bin_dir/secguard.exe" ] && bin="$bin_dir/secguard.exe"
    if [ -f "$bin" ] && [ -x "$bin" ]; then
        sg_check ok "Binary exists and executable: $bin"
        # 版本匹配（secguard --version 输出含版本号）
        if "$bin" --version 2>/dev/null | grep -q "$pkg_version"; then
            sg_check ok "Binary version matches: $pkg_version"
        else
            sg_check fail "Binary version mismatch (expected $pkg_version)"
        fi
    else
        sg_check fail "Binary missing or not executable: $bin"
    fi

    # OpenCode 检查
    if [ "$platform" = "all" ] || [ "$platform" = "opencode" ]; then
        local oc_dir="$oc_prefix/extensions/secguard-clang"
        echo ""
        echo "OpenCode extension ($oc_dir):"
        [ -f "$oc_dir/extension.json" ] && sg_check ok "extension.json" || sg_check fail "extension.json"
        [ -f "$oc_dir/opencode.json" ] && sg_check ok "opencode.json" || sg_check fail "opencode.json"
        [ -f "$oc_dir/commands/secguard.md" ] && sg_check ok "commands/secguard.md" || sg_check fail "commands/secguard.md"
        [ -f "$oc_dir/agents/security-auditor.md" ] && sg_check ok "agents/security-auditor.md" || sg_check fail "agents/security-auditor.md"
        local skill_count
        skill_count=$(find "$oc_dir/skills" -name SKILL.md 2>/dev/null | wc -l | tr -d ' ')
        if [ "$skill_count" -ge 14 ]; then
            sg_check ok "Skills count: $skill_count (>=14)"
        else
            sg_check fail "Skills count: $skill_count (expected >=14)"
        fi
    fi

    # ClaudeCode 检查
    if [ "$platform" = "all" ] || [ "$platform" = "claude-code" ]; then
        local cc_dir="$cc_prefix/skills/secguard-clang"
        echo ""
        echo "ClaudeCode plugin ($cc_dir):"
        [ -f "$cc_dir/.claude-plugin/plugin.json" ] && sg_check ok ".claude-plugin/plugin.json" || sg_check fail ".claude-plugin/plugin.json"
        [ -f "$cc_dir/commands/secguard.md" ] && sg_check ok "commands/secguard.md" || sg_check fail "commands/secguard.md"
        [ -f "$cc_dir/agents/security-auditor.md" ] && sg_check ok "agents/security-auditor.md" || sg_check fail "agents/security-auditor.md"
        [ -f "$cc_dir/hooks/hooks.json" ] && sg_check ok "hooks/hooks.json" || sg_check fail "hooks/hooks.json"
        local skill_count
        skill_count=$(find "$cc_dir/skills" -name SKILL.md 2>/dev/null | wc -l | tr -d ' ')
        if [ "$skill_count" -ge 14 ]; then
            sg_check ok "Skills count: $skill_count (>=14)"
        else
            sg_check fail "Skills count: $skill_count (expected >=14)"
        fi
        if sg_check_permissions_merged "$cc_prefix/settings.json" 2>/dev/null; then
            sg_check ok "Permissions merged in settings.json"
        else
            sg_check fail "Permissions not fully merged in settings.json"
        fi
    fi

    echo ""
    echo "─────────────────────────────────────────────────────────"
    echo "Result: $pass passed, $fail failed"
    [ "$fail" -eq 0 ]
}

# 清理旧版"平铺式"安装遗留（迁移到 extensions/ 之前的设计）。
# 早期版本把 tools/skills/agents 直接装到 $OC_PREFIX 下，现在统一收敛到
# $OC_PREFIX/extensions/secguard-clang/。安装与卸载都会调用，避免两处定义漂移
# （尤其避免 de-drift 整改后旧副本仍残留硬编码类型清单）。仅移除 secguard 自身文件，
# 其它工具的平铺内容（如 $OC_PREFIX/skills/arkcli-*）不受影响。
# 用法：sg_cleanup_legacy_flat <oc_prefix> <pkg_dir>
sg_cleanup_legacy_flat() {
    local oc_prefix="$1"
    local pkg_dir="$2"
    local f skill_dir skill_name
    # 旧平铺工具
    for f in "$oc_prefix"/tools/secguard_*.ts; do
        [ -f "$f" ] && rm -f "$f"
    done
    # 旧平铺 skills（按 shared/skills 的权威清单逐个比对删除）
    for skill_dir in "$pkg_dir"/shared/skills/*/; do
        [ -d "$skill_dir" ] || continue
        skill_name=$(basename "$skill_dir")
        [ -d "$oc_prefix/skills/$skill_name" ] && rm -rf "$oc_prefix/skills/$skill_name"
    done
    # 旧平铺 agent / plugin
    rm -f "$oc_prefix/agents/security-auditor.md"
    rm -f "$oc_prefix/plugins/secguard-context.ts"
}

# @@SG_INJECT_END@@
# ──────────────────────────────────────────────────────────────
# 可注入区结束
# ──────────────────────────────────────────────────────────────

# ──────────────────────────────────────────────────────────────
# 构建侧专用函数（不注入 zip，仅源码树中 source 使用）
# ──────────────────────────────────────────────────────────────

# 版本解析：三级回退
# 用法：resolve_version <explicit>
# 优先级：显式参数 > VERSION 文件 > git describe > 0.0.0-dev
# 统一去除前导 v（git tag 为 v0.1.0，包名/ldflags 用 0.1.0）
resolve_version() {
    local explicit="$1"
    if [ -n "$explicit" ]; then
        echo "$explicit" | sed 's/^v//'
        return 0
    fi
    if [ -n "${PROJECT_ROOT:-}" ] && [ -f "$PROJECT_ROOT/VERSION" ]; then
        local v
        v=$(tr -d '[:space:]' < "$PROJECT_ROOT/VERSION")
        if [ -n "$v" ]; then
            echo "$v"
            return 0
        fi
    fi
    if command -v git >/dev/null 2>&1; then
        local gv
        gv=$(git -C "${PROJECT_ROOT:-.}" describe --tags --always --dirty 2>/dev/null) || gv=""
        if [ -n "$gv" ]; then
            echo "$gv" | sed 's/^v//'
            return 0
        fi
    fi
    echo "0.0.0-dev"
}

# 跨平台构建单个目标
# 用法：build_target <goos> <goarch> <version>
# 成功 stdout 输出二进制绝对路径；失败返回非 0
#
# 交叉编译策略（CGO 必需，tree-sitter 为 C 实现）：
#   - darwin：用系统 clang，原生 + amd64/arm64 交叉（macOS SDK 支持双架构）
#   - linux：用 zig cc -target <arch>-linux-musl 静态链接（与 CHANGELOG 一致）
#   - windows：用 zig cc -target <arch>-windows-gnu
# 可通过 SG_CC / SG_CXX 覆盖；zig 需在 PATH 或 ZIG 环境变量指向其二进制。
build_target() {
    local goos="$1"
    local goarch="$2"
    local version="$3"
    local bin_name="secguard-${goos}-${goarch}"
    local out="$DIST_DIR/$bin_name"
    local zig="${ZIG:-}"
    [ -z "$zig" ] && command -v zig >/dev/null 2>&1 && zig="$(command -v zig)"
    local zig_arch
    case "$goarch" in
        amd64) zig_arch="x86_64" ;;
        arm64) zig_arch="aarch64" ;;
        *)     zig_arch="$goarch" ;;
    esac
    local cc cxx cflags=""
    case "$goos" in
        linux)
            [ -z "$zig" ] && { echo "ERROR: zig required for linux cross-compile (set ZIG or add to PATH)" >&2; return 1; }
            cc="$zig cc -target ${zig_arch}-linux-musl"
            cxx="$zig c++ -target ${zig_arch}-linux-musl"
            ;;
        windows)
            [ -z "$zig" ] && { echo "ERROR: zig required for windows cross-compile (set ZIG or add to PATH)" >&2; return 1; }
            cc="$zig cc -target ${zig_arch}-windows-gnu"
            cxx="$zig c++ -target ${zig_arch}-windows-gnu"
            # cgo 导出头在 Windows 目标下会触发 tree-sitter 回调重声明的
            # -Wdll-attribute-on-redeclaration 警告，属已知良性噪音，静默之。
            cflags="-Wno-dll-attribute-on-redeclaration"
            out="$DIST_DIR/$bin_name.exe"
            ;;
        *)
            cc="${SG_CC:-cc}"
            cxx="${SG_CXX:-c++}"
            ;;
    esac
    (
        cd "$SGRE_DIR"
        GOOS="$goos" GOARCH="$goarch" CGO_ENABLED=1 \
        CC="$cc" CXX="$cxx" CGO_CFLAGS="$cflags" CGO_CXXFLAGS="$cflags" \
        GONOSUMDB='*' GOFLAGS=-mod=mod \
        GOCACHE="$SGRE_DIR/.gocache" TMPDIR="$SGRE_DIR/.gotmp" \
        ZIG_GLOBAL_CACHE_DIR="$SGRE_DIR/.zig-cache/global" \
        ZIG_LOCAL_CACHE_DIR="$SGRE_DIR/.zig-cache/local" \
        go build -trimpath \
          -ldflags "-X github.com/DannyAn/secguard-clang/internal/cli.Version=${version}" \
          -o "$out" ./cmd/secguard
    ) || return 1
    chmod +x "$out"
    echo "$out"
}

# 计算 sha256
# 用法：sha256_file <file_path>
sha256_file() {
    shasum -a 256 "$1" | cut -d' ' -f1
}

# 写包内 manifest.json
# 用法：write_manifest <pkg_root> <version> <targets_csv> <skills_csv>
write_manifest() {
    local pkg_root="$1"
    local version="$2"
    local targets_csv="$3"
    local skills_csv="$4"
    local go_version
    go_version=$(go version 2>/dev/null | head -1 || echo "unknown")
    python3 -c "
import json, datetime, os, hashlib
pkg_root = '''$pkg_root'''
version = '''$version'''
targets_csv = '''$targets_csv'''
skills_csv = '''$skills_csv'''
go_version = '''$go_version'''
targets = [t for t in targets_csv.split(',') if t]
skills = [s for s in skills_csv.split(',') if s]
files = {}
for dirpath, dirnames, filenames in os.walk(pkg_root):
    for fn in filenames:
        full = os.path.join(dirpath, fn)
        rel = os.path.relpath(full, pkg_root)
        if fn in ('manifest.json',):
            continue
        with open(full, 'rb') as f:
            h = hashlib.sha256(f.read()).hexdigest()
        files[rel] = h
manifest = {
    'version': version,
    'build_date': datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ'),
    'go_version': go_version,
    'targets': targets,
    'skills': skills,
    'files': files,
}
with open(os.path.join(pkg_root, 'manifest.json'), 'w') as f:
    json.dump(manifest, f, indent=2)
    f.write('\n')
"
}

# 构建侧模板展开别名（委托 sg_expand_includes）
# 用法：expand_includes <input_file> <output_file> <shared_dir>
expand_includes() {
    sg_expand_includes "$1" "$2" "$3"
}

# 提取可注入区内容
# 用法：extract_inject_block <lib_sh_path>
# stdout 输出 @@SG_INJECT_START@@ 与 @@SG_INJECT_END@@ 之间的内容
extract_inject_block() {
    local lib_sh_path="$1"
    awk '
        /^# @@SG_INJECT_START@@$/ { in_block=1; next }
        /^# @@SG_INJECT_END@@$/   { in_block=0; next }
        in_block { print }
    ' "$lib_sh_path"
}

# 将可注入区注入模板占位标记
# 用法：inject_into <template_path> <inject_block_file>
# stdout 输出注入后完整脚本
inject_into() {
    local template_path="$1"
    local inject_file="$2"
    if ! grep -q '@@SG_LIB_INJECT@@' "$template_path"; then
        echo "ERROR: template $template_path missing @@SG_LIB_INJECT@@ marker" >&2
        return 1
    fi
    python3 -c "
template_path = '''$template_path'''
inject_file = '''$inject_file'''
with open(template_path, 'r') as f:
    content = f.read()
with open(inject_file, 'r') as f:
    inject_block = f.read()
content = content.replace('# @@SG_LIB_INJECT@@', inject_block)
print(content)
"
}