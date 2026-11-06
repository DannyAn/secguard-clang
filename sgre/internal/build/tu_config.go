package build

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/DannyAn/secguard-clang/internal/typeinfo"
)

// TUConfig 是单个编译单元的编译配置（GAP-1038 Phase 1a，评审 P0-1）。
// Type Layout 按 (TU, Config, Type) 隔离，同名类型跨 TU/宏配置不得合并。
type TUConfig struct {
	File        string         // 编译的源文件路径
	Directory   string         // 编译工作目录
	Target      string         // 目标 triple（--target= / -target）
	ABI         typeinfo.ABI   // 推导出的 ABI
	PackStruct  int            // -fpack-struct=N（字节），0=未设置（自然对齐）
	ShortEnums  bool           // -fshort-enums
	Defines     map[string]int // 该 TU 的 -D 数值宏
	IncludeDirs []string       // 该 TU 的 -I 目录
	ConfigKey   string         // 派生的配置摘要 key（用于 LayoutKey.Config）
}

// parseTUConfig 从一个 compile_commands entry 的参数列表提取 per-TU 配置。
// file/directory 来自 entry 的 JSON 字段，args 是 arguments 数组或 command 分词。
func parseTUConfig(file, directory string, args []string) TUConfig {
	tc := TUConfig{
		File:      file,
		Directory: directory,
		Defines:   map[string]int{},
	}
	for i := 0; i < len(args); i++ {
		tok := args[i]
		next := func() string {
			if i+1 < len(args) {
				return args[i+1]
			}
			return ""
		}
		switch {
		case tok == "-m32":
			tc.ABI = typeinfo.ABIILP32
		case tok == "-m64":
			tc.ABI = typeinfo.ABILP64
		case strings.HasPrefix(tok, "--target="):
			tc.Target = tok[len("--target="):]
			tc.ABI = abiFromTriple(tc.Target)
		case tok == "--target" || tok == "-target":
			if v := next(); v != "" {
				tc.Target = v
				tc.ABI = abiFromTriple(v)
			}
		case tok == "-fpack-struct":
			tc.PackStruct = 1
		case strings.HasPrefix(tok, "-fpack-struct="):
			if n, err := strconv.Atoi(tok[len("-fpack-struct="):]); err == nil && n > 0 {
				tc.PackStruct = n
			}
		case tok == "-fshort-enums":
			tc.ShortEnums = true
		case tok == "-D":
			if v := next(); v != "" {
				applyTUDefine(&tc, v)
			}
		case strings.HasPrefix(tok, "-D") && len(tok) > 2:
			applyTUDefine(&tc, tok[2:])
		case tok == "-I":
			if v := next(); v != "" {
				tc.IncludeDirs = append(tc.IncludeDirs, v)
			}
		case strings.HasPrefix(tok, "-I") && len(tok) > 2:
			tc.IncludeDirs = append(tc.IncludeDirs, tok[2:])
		}
	}
	if tc.ABI == "" {
		tc.ABI = typeinfo.ABILP64
	}
	tc.ConfigKey = deriveConfigKey(tc)
	return tc
}

// abiFromTriple 从 target triple 推导 ABI。
// windows-* → LLP64；其余 64-bit → LP64；显式 32-bit 后缀 → ILP32。
// abiFromTriple 从 target triple 推导 ABI。
// windows-* → 64-bit 为 LLP64、32-bit 为 ILP32；其余 64-bit → LP64、32-bit → ILP32。
// 32/64 位按架构名判定（i686/armv7/riscv32/wasm32 等为 32 位；x86_64/aarch64/
// arm64/riscv64/mips64/ppc64/s390x/wasm64 等为 64 位），不能只看 windows 前缀。
func abiFromTriple(triple string) typeinfo.ABI {
	t := strings.ToLower(strings.TrimSpace(triple))
	bits64 := false
	for _, arch := range []string{
		"x86_64", "amd64", "aarch64", "arm64", "riscv64", "mips64", "mips64el",
		"ppc64", "powerpc64", "s390x", "sparc64", "loongarch64", "wasm64",
	} {
		if strings.Contains(t, arch) {
			bits64 = true
			break
		}
	}
	if bits64 {
		if strings.Contains(t, "windows") || strings.Contains(t, "mingw") {
			return typeinfo.ABILLP64
		}
		return typeinfo.ABILP64
	}
	return typeinfo.ABIILP32
}

func applyTUDefine(tc *TUConfig, def string) {
	name, val, ok := splitDefine(def)
	if !ok {
		return
	}
	tc.Defines[name] = val
}

// deriveConfigKey 生成配置摘要 key：abi + pack + short-enums + 排序后的 defines。
// 同一类型在不同 ConfigKey 下得到不同 LayoutKey，不合并。
func deriveConfigKey(tc TUConfig) string {
	var b strings.Builder
	b.WriteString(string(tc.ABI))
	if tc.PackStruct > 0 {
		b.WriteString(":pack=")
		b.WriteString(strconv.Itoa(tc.PackStruct))
	}
	if tc.ShortEnums {
		b.WriteString(":short-enums")
	}
	if len(tc.Defines) > 0 {
		keys := make([]string, 0, len(tc.Defines))
		for k := range tc.Defines {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		b.WriteString(":D=")
		for i, k := range keys {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(strconv.Itoa(tc.Defines[k]))
		}
	}
	return b.String()
}

// TUForFile 返回该文件对应的 TUConfig。无匹配 entry 时返回 nil，
// 调用方应据此将 layout provenance 降级为 assumed_default_abi。
//
// compile_commands 的 file 通常是相对 entry 的 directory 的路径，而调用方
// （indexer）给的是绝对路径；两种形态都按 cleaner 绝对路径比较。
func (c *CompileCommands) TUForFile(file string) *TUConfig {
	if c == nil {
		return nil
	}
	want := filepath.Clean(file)
	for i := range c.TUs {
		entry := c.TUs[i]
		rel := filepath.Clean(entry.File)
		if rel == want {
			return &c.TUs[i]
		}
		if !filepath.IsAbs(rel) && entry.Directory != "" {
			if filepath.Clean(filepath.Join(entry.Directory, rel)) == want {
				return &c.TUs[i]
			}
		}
		if !filepath.IsAbs(want) && entry.Directory != "" {
			if filepath.Join(entry.Directory, want) == rel {
				return &c.TUs[i]
			}
		}
	}
	return nil
}
