package repofacts

import (
	"strings"

	"github.com/DannyAn/secguard-clang/internal/parser"
	"github.com/DannyAn/secguard-clang/internal/typeinfo"
)

// structDecl 是一个 struct/union 声明的中间表示，用于布局计算。
type structDecl struct {
	name    string
	isUnion bool
	fields  []typeinfo.FieldSpec
	// unknownReason 非空时该类型布局不可计算（packed/bitfield/冲突等），
	// buildLayouts 直接返回 Unknown layout，不按自然对齐猜。
	unknownReason string
}

// extractFieldSpecs 从一个 struct/union 自身的 field_declaration_list 提取字段规格。
// macros 用于解析数组容量宏。
//
// 只遍历该类型自己的直接 field_declaration 子节点：FindAll 是递归的，会把内联
// 嵌套 struct/union 定义（struct Outer { struct Inner {...} n; }）的字段也收进
// 外层，导致字段偏移整体错位（误报）。嵌套类型由 collectStructDecls 单独收集。
func extractFieldSpecs(ss parser.Node, macros map[string]int) []typeinfo.FieldSpec {
	list := ss.FindFirst("field_declaration_list")
	if list == nil {
		return nil
	}
	var out []typeinfo.FieldSpec
	for _, fd := range list.NamedChildren() {
		if fd.Kind() != "field_declaration" {
			continue
		}
		typ := fieldDeclTypeSpelling(fd)
		isStruct, isUnion := fieldDeclIsAggregate(fd)
		for _, spec := range fieldDeclarators(fd, typ, isStruct, isUnion, macros) {
			out = append(out, spec)
		}
	}
	return out
}

// fieldDeclTypeSpelling 返回 field_declaration 的类型拼写。
func fieldDeclTypeSpelling(fd parser.Node) string {
	var parts []string
	for _, c := range fd.NamedChildren() {
		switch c.Kind() {
		case "primitive_type", "type_identifier", "sized_type_specifier":
			parts = append(parts, strings.TrimSpace(c.Text()))
		case "struct_specifier", "union_specifier", "enum_specifier":
			// struct Foo → "Foo"（用于 resolver 查询）
			for _, cc := range c.NamedChildren() {
				if cc.Kind() == "type_identifier" {
					parts = append(parts, strings.TrimSpace(cc.Text()))
				}
			}
		}
	}
	return strings.Join(parts, " ")
}

// fieldDeclIsAggregate 报告 field_declaration 的类型是否是 struct/union。
func fieldDeclIsAggregate(fd parser.Node) (isStruct, isUnion bool) {
	for _, c := range fd.NamedChildren() {
		switch c.Kind() {
		case "struct_specifier":
			return true, false
		case "union_specifier":
			return false, true
		}
	}
	return false, false
}

// fieldDeclarators 从一个 field_declaration 提取所有 declarator 的 FieldSpec。
//
// 只从声明自身的 declarator 直接子节点向下找：FindAll 是递归的，会钻进内联
// struct/union 定义的字段列表（struct { int arr[4]; } n; 会把 arr 当成外层
// 字段），导致外层布局错误。
func fieldDeclarators(fd parser.Node, typ string, isStruct, isUnion bool, macros map[string]int) []typeinfo.FieldSpec {
	var out []typeinfo.FieldSpec
	seen := map[string]bool{}
	add := func(spec typeinfo.FieldSpec) {
		if spec.Name == "" || seen[spec.Name] {
			return
		}
		seen[spec.Name] = true
		spec.TypeSpelling = typ
		spec.IsStruct = isStruct
		spec.IsUnion = isUnion
		out = append(out, spec)
	}
	for _, c := range fd.NamedChildren() {
		switch c.Kind() {
		case "array_declarator":
			name := declaratorName(c)
			if name == "" {
				continue
			}
			spec := typeinfo.FieldSpec{Name: name, IsArray: true}
			if n, ok := arrayTotalCount(c, macros); ok {
				spec.ArrayCount = n
			}
			if hasPointerInArray(c) {
				spec.IsPointer = true
			}
			add(spec)
		case "pointer_declarator", "function_declarator":
			if name := declaratorName(c); name != "" {
				add(typeinfo.FieldSpec{Name: name, IsPointer: true})
			}
		case "parenthesized_declarator":
			if name := declaratorName(c); name != "" {
				add(typeinfo.FieldSpec{Name: name, IsPointer: len(c.FindAll("pointer_declarator")) > 0})
			}
		case "field_identifier":
			add(typeinfo.FieldSpec{Name: strings.TrimSpace(c.Text())})
		}
	}
	// 位域检测：用索引写回（修复 P0-4 no-op），并标记整个 struct 为 unknown。
	for _, c := range fd.NamedChildren() {
		if c.Kind() != "bitfield_clause" {
			continue
		}
		if n := bitfieldWidth(c); n > 0 {
			for i := range out {
				out[i].BitWidth = n
			}
		}
	}
	return out
}

// arrayTotalCount 返回多维数组声明的总元素数（int a[2][3] → 6）。任一维
// 不是常量（含柔性数组 []）时返回 ok=false，由调用方把 ArrayCount 留 0。
// typeinfo 的数组分支只在 count>0 时乘 count，因此未知长度数组仍按单元素
// 计算；layout-OOB detector 已按 IsArray 跳过全部数组字段。
func arrayTotalCount(ad parser.Node, macros map[string]int) (int, bool) {
	total := 1
	cur := ad
	for {
		n, _, ok := arrayCapacity(cur, macros)
		if !ok {
			return 0, false
		}
		total *= n
		found := false
		for _, c := range cur.NamedChildren() {
			if c.Kind() == "array_declarator" {
				cur = c
				found = true
				break
			}
		}
		if !found {
			return total, true
		}
	}
}

func hasPointerInArray(ad parser.Node) bool {
	for _, p := range ad.FindAll("pointer_declarator") {
		_ = p
		return true
	}
	return false
}

func bitfieldWidth(bc parser.Node) int {
	for _, c := range bc.NamedChildren() {
		if c.Kind() == "number_literal" {
			return parseInt(c.Text())
		}
	}
	return 0
}

// collectStructDecls 遍历 AST 收集所有 struct/union 声明。
func collectStructDecls(root parser.Node, macros map[string]int) []structDecl {
	var decls []structDecl
	// #pragma pack changes field alignment without an attribute on the struct
	// text. Resolving its push/pop region is out of MVP scope, so any pack pragma
	// in the TU conservatively makes every type in it unknown (never guess the
	// natural layout).
	packPragma := false
	for _, pc := range root.FindAll("preproc_call") {
		text := pc.Text()
		if strings.Contains(text, "pragma") && strings.Contains(text, "pack") {
			packPragma = true
			break
		}
	}
	for _, kind := range []string{"struct_specifier", "union_specifier"} {
		for _, ss := range root.FindAll(kind) {
			if ss.FindFirst("field_declaration_list") == nil {
				continue
			}
			keys := typeKeys(ss)
			if len(keys) == 0 {
				continue
			}
			fields := extractFieldSpecs(ss, macros)
			reason := layoutUnknownReason(ss, fields)
			if reason == "" && packPragma {
				reason = "#pragma pack in translation unit — MVP does not compute packed layout"
			}
			for _, key := range keys {
				decls = append(decls, structDecl{
					name:          key,
					isUnion:       kind == "union_specifier",
					fields:        fields,
					unknownReason: reason,
				})
			}
		}
	}
	return decls
}

// layoutUnknownReason 检测导致布局不可精确计算的语言特性。
// MVP 策略：packed/aligned 属性、位域（含匿名位域）、匿名 struct/union 成员 →
// unknown，不按自然对齐猜（P0-3/P0-4 / nested-aggregate follow-up）。
func layoutUnknownReason(ss parser.Node, fields []typeinfo.FieldSpec) string {
	text := ss.Text()
	if hasPackedAttribute(text) {
		return "packed/aligned attribute — MVP does not compute packed layout"
	}
	for _, f := range fields {
		if f.BitWidth > 0 {
			return "bitfield member — MVP does not compute bitfield layout"
		}
	}
	// A flexible array member is legal only as the LAST member; an
	// unknown-count array followed by another field would make every following
	// offset a guess (its true size is unknowable from the declaration).
	for i, f := range fields {
		if f.IsArray && f.ArrayCount <= 0 && i != len(fields)-1 {
			return "unknown-length array member before another field — MVP does not guess offsets"
		}
	}
	// 直接子节点里检查：匿名位域（int :2; 没有 field_identifier）不会进入
	// fields，但同样占位；匿名 struct/union 成员（无 declarator）的成员
	// 与外层重叠/展开，扁平的顺序布局无法表达，必须整体降级为 unknown。
	list := ss.FindFirst("field_declaration_list")
	if list == nil {
		return ""
	}
	for _, fd := range list.NamedChildren() {
		if fd.Kind() != "field_declaration" {
			continue
		}
		hasAnonymousAggregate := false
		hasDeclarator := false
		for _, c := range fd.NamedChildren() {
			switch c.Kind() {
			case "bitfield_clause":
				return "bitfield member — MVP does not compute bitfield layout"
			case "struct_specifier", "union_specifier":
				if c.FindFirst("field_declaration_list") != nil {
					hasAnonymousAggregate = true
				}
			case "field_identifier", "pointer_declarator", "array_declarator",
				"function_declarator", "parenthesized_declarator", "init_declarator":
				hasDeclarator = true
			}
		}
		if hasAnonymousAggregate && !hasDeclarator {
			return "anonymous aggregate member — MVP does not flatten it"
		}
	}
	return ""
}

// hasPackedAttribute 报告类型文本是否包含 __attribute__((packed)) 或
// __attribute__((aligned))。文本匹配是保守的：只要疑似出现就标 unknown，
// 宁可不报也不误报。
func hasPackedAttribute(text string) bool {
	return strings.Contains(text, "__attribute__") &&
		(strings.Contains(text, "packed") || strings.Contains(text, "aligned"))
}

// buildLayouts 计算所有 struct/union 的 TypeLayout。
//
// provenance 由调用方决定：有 compile_commands 且配置完整 → derived_from_complete_config；
// 无 compile_commands → assumed_default_abi。任一类型无法解析 → unknown。
//
// 同名类型跨 TU 冲突 → unknown（P0-1）：不取第一个，不合并。
// packed/bitfield → unknown（P0-3/P0-4）：不按自然对齐猜。
// 嵌套类型通过递归 + memoization 解析；循环值嵌套在 C 中非法，遇到时标 unknown。
func buildLayouts(decls []structDecl, abi typeinfo.ABI, pack int, prov typeinfo.Provenance) map[typeinfo.LayoutKey]typeinfo.TypeLayout {
	layouts := map[typeinfo.LayoutKey]typeinfo.TypeLayout{}
	byName := map[string]typeinfo.TypeLayout{}
	resolving := map[string]bool{}

	// P0-1: 检测同名类型冲突。同名类型出现多次且 fields 不同 → unknown。
	nameCount := map[string]int{}
	nameConflict := map[string]bool{}
	for i, d := range decls {
		nameCount[d.name]++
		if nameCount[d.name] > 1 {
			prev := decls[0]
			for j := 1; j < i; j++ {
				if decls[j].name == d.name {
					prev = decls[j]
					break
				}
			}
			if !sameFields(prev.fields, d.fields) {
				nameConflict[d.name] = true
			}
		}
	}

	unknownLayout := func(name, reason string) typeinfo.TypeLayout {
		return typeinfo.TypeLayout{
			Key:        typeinfo.LayoutKey{Type: name},
			Name:       name,
			Provenance: prov,
			Unknown:    reason,
		}
	}

	var resolve typeinfo.LayoutResolver
	resolve = func(typeSpelling string) (typeinfo.TypeLayout, bool) {
		if tl, ok := byName[typeSpelling]; ok {
			return tl, true
		}
		if resolving[typeSpelling] {
			return typeinfo.TypeLayout{Unknown: "circular value nesting"}, true
		}
		for _, d := range decls {
			if d.name == typeSpelling {
				if nameConflict[d.name] {
					tl := unknownLayout(d.name, "cross-TU name conflict — same type name with different fields")
					byName[d.name] = tl
					layouts[typeinfo.LayoutKey{Type: d.name}] = tl
					return tl, true
				}
				if d.unknownReason != "" {
					tl := unknownLayout(d.name, d.unknownReason)
					byName[d.name] = tl
					layouts[typeinfo.LayoutKey{Type: d.name}] = tl
					return tl, true
				}
				resolving[typeSpelling] = true
				tl := computeOneLayout(d, abi, pack, resolve)
				tl.Provenance = prov
				byName[typeSpelling] = tl
				layouts[typeinfo.LayoutKey{Type: d.name}] = tl
				delete(resolving, typeSpelling)
				return tl, true
			}
		}
		return typeinfo.TypeLayout{}, false
	}

	for _, d := range decls {
		if _, exists := byName[d.name]; exists {
			continue
		}
		if nameConflict[d.name] {
			tl := unknownLayout(d.name, "cross-TU name conflict — same type name with different fields")
			byName[d.name] = tl
			layouts[typeinfo.LayoutKey{Type: d.name}] = tl
			continue
		}
		if d.unknownReason != "" {
			tl := unknownLayout(d.name, d.unknownReason)
			byName[d.name] = tl
			layouts[typeinfo.LayoutKey{Type: d.name}] = tl
			continue
		}
		tl := computeOneLayout(d, abi, pack, resolve)
		tl.Provenance = prov
		byName[d.name] = tl
		layouts[typeinfo.LayoutKey{Type: d.name}] = tl
	}
	return layouts
}

// sameFields 报告两组 FieldSpec 是否在结构上等价（名称+类型+数组+指针）。
func sameFields(a, b []typeinfo.FieldSpec) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Name != b[i].Name || a[i].TypeSpelling != b[i].TypeSpelling ||
			a[i].IsArray != b[i].IsArray || a[i].ArrayCount != b[i].ArrayCount ||
			a[i].IsPointer != b[i].IsPointer || a[i].IsStruct != b[i].IsStruct ||
			a[i].IsUnion != b[i].IsUnion {
			return false
		}
	}
	return true
}

// computeOneLayout 计算单个 struct/union 的布局。
func computeOneLayout(d structDecl, abi typeinfo.ABI, pack int, resolve typeinfo.LayoutResolver) typeinfo.TypeLayout {
	key := typeinfo.LayoutKey{Type: d.name}
	if d.isUnion {
		return typeinfo.LayoutUnion(abi, key, d.fields, resolve)
	}
	return typeinfo.LayoutStruct(abi, key, d.fields, pack, resolve)
}

// layoutProvenance 根据 compile_commands 可用性决定 layout provenance（评审 P0-2）。
//
// Phase 1 MVP: 始终返回 assumed_default_abi——"有 compile_commands"不等于"配置完整"，
// 必须检查 target + pack/alignment + short-enums + 宏配置完整后才给
// derived_from_complete_config。该完整检查在 Phase 2 接线；此处保守降级。
func layoutProvenance(hasCompileCommands bool) typeinfo.Provenance {
	_ = hasCompileCommands
	return typeinfo.ProvenanceAssumedDefaultABI
}
