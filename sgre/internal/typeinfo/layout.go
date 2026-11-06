package typeinfo

import "strings"

// LayoutKey 是一个 TypeLayout 事实的复合键（评审 P0-1）。
// 同名类型在不同 TU/编译配置下是不同布局，不能合并。
type LayoutKey struct {
	TU     string // 编译单元 / 编译配置 id；空表示不适用
	Config string // target + pack/alignment/short-enums/macro 配置摘要
	Type   string // struct tag / typedef alias
}

// FieldSpec 是布局算法的输入：一个 struct/union 字段的声明信息。
// repofacts 负责从 parser.Node 提取 FieldSpec，typeinfo 负责计算布局。
type FieldSpec struct {
	Name         string
	TypeSpelling string // 规范化后的类型拼写（如 "int", "char *", "struct Foo"）
	IsPointer    bool
	IsArray      bool
	ArrayCount   int  // IsArray=true 时有效；0 表示未知
	IsStruct     bool // struct/union 嵌套（需要递归）
	IsUnion      bool
	BitWidth     int // 位域宽度，0=非位域；>0 触发 unknown（MVP 不支持）
	Pack         int // 该字段/类型的 pack 对齐（字节），0=使用自然对齐
	AlignAttr    int // __attribute__((aligned(N)))，0=无
}

// FieldLayout 是布局算法的输出：一个字段的布局信息。
type FieldLayout struct {
	Name       string
	Offset     int // 字节偏移（struct 内）
	Size       int // 字节大小
	Align      int // 字节对齐
	ArrayCount int
	BitWidth   int
	IsPointer  bool
	// IsArray marks a fixed-size OR flexible/unknown-count array member. The
	// layout-OOB detector skips array members in MVP (an element access is not
	// the whole array access), so it must not infer "not an array" from
	// ArrayCount==0 (a flexible array member legitimately has count 0).
	IsArray bool
}

// TypeLayout 是一个类型的完整布局。
type TypeLayout struct {
	Key        LayoutKey
	Name       string
	Size       int    // 字节
	Align      int    // 字节
	Kind       string // "primitive" | "struct" | "union" | "array" | "pointer" | "unknown"
	Fields     []FieldLayout
	Provenance Provenance
	Source     string
	Unknown    string // 非空表示不可用原因；非空时 Size/Align/Fields 不可信
}

// LayoutResolver 解析嵌套类型的布局。typeinfo 是纯函数包，不依赖 parser/repofacts，
// 所以嵌套 struct/union/typedef 的布局由调用方通过此回调提供。
// 返回 ok=false 表示该类型布局未知（触发整个外层 struct → unknown）。
type LayoutResolver func(typeSpelling string) (TypeLayout, bool)

// alignUp 把 offset 向上对齐到 align 的倍数。align<=0 时返回 offset。
func alignUp(offset, align int) int {
	if align <= 0 {
		return offset
	}
	r := offset % align
	if r == 0 {
		return offset
	}
	return offset + align - r
}

// fieldSizeAlign 计算单个字段的字节大小与对齐。
// 返回 ok=false 表示该字段无法解析（位域、未知类型、嵌套未知）。
func fieldSizeAlign(abi ABI, fs FieldSpec, resolve LayoutResolver) (size, align int, ok bool) {
	if fs.BitWidth > 0 {
		return 0, 0, false // MVP: 位域 → unknown
	}
	// A flexible/unknown-count array member contributes 0 bytes to sizeof (the
	// C11 FAM rule), but its ELEMENT alignment still affects the following
	// offset/struct alignment. Returning the element size here (the old
	// behavior) made `struct F { int n; char data[]; }` one byte larger than its
	// real sizeof and let the detector compare a `data[i]` access as a whole
	// array. The layout-OOB detector skips array members entirely; a mid-struct
	// unknown-count array is rejected as unknown by the census.
	if fs.IsArray && fs.ArrayCount <= 0 {
		elem := fs
		elem.IsArray = false
		elem.ArrayCount = 0
		_, elemAlign, elemOK := fieldSizeAlign(abi, elem, resolve)
		if !elemOK {
			return 0, 0, false
		}
		return 0, elemAlign, true
	}
	if fs.IsPointer || IsPointerSpelling(fs.TypeSpelling) {
		size = PointerBits(abi) / 8
		align = PointerAlign(abi)
		if fs.IsArray && fs.ArrayCount > 0 {
			size *= fs.ArrayCount
		}
		if fs.AlignAttr > 0 {
			align = fs.AlignAttr
		}
		return size, align, true
	}
	if fs.IsStruct || fs.IsUnion {
		if resolve == nil {
			return 0, 0, false
		}
		inner, found := resolve(fs.TypeSpelling)
		if !found || inner.Unknown != "" {
			return 0, 0, false
		}
		size, align = inner.Size, inner.Align
		if fs.IsArray && fs.ArrayCount > 0 {
			size *= fs.ArrayCount
		}
		if fs.Pack > 0 && fs.Pack < align {
			align = fs.Pack
		}
		if fs.AlignAttr > 0 {
			align = fs.AlignAttr
		}
		return size, align, true
	}
	// 基本类型或 typedef 到基本类型
	spelling := strings.TrimSpace(fs.TypeSpelling)
	if bits, found := PrimitiveBits(abi, spelling); found {
		size = bits / 8
		if a, ok2 := PrimitiveAlign(abi, spelling); ok2 {
			align = a
		} else {
			align = size
		}
		if fs.IsArray && fs.ArrayCount > 0 {
			size *= fs.ArrayCount
		}
		if fs.Pack > 0 && fs.Pack < align {
			align = fs.Pack
		}
		if fs.AlignAttr > 0 {
			align = fs.AlignAttr
		}
		return size, align, true
	}
	// 尝试通过 resolver 解析 typedef
	if resolve != nil {
		if inner, found := resolve(spelling); found && inner.Unknown == "" {
			size, align = inner.Size, inner.Align
			if fs.IsArray && fs.ArrayCount > 0 {
				size *= fs.ArrayCount
			}
			if fs.Pack > 0 && fs.Pack < align {
				align = fs.Pack
			}
			if fs.AlignAttr > 0 {
				align = fs.AlignAttr
			}
			return size, align, true
		}
	}
	return 0, 0, false
}

// LayoutStruct 计算 struct 布局：按声明顺序，offset = alignUp(offset, fieldAlign)，
// structAlign = max(fieldAlign)，size = alignUp(offset, structAlign)。
// pack>0 表示 -fpack-struct=N / #pragma pack(N) 全局 pack（取 fieldAlign = min(naturalAlign, pack)）。
//
// 任一字段无法解析 → 整个 struct Unknown（MVP 不输出部分偏移，评审 P0-1）。
func LayoutStruct(abi ABI, key LayoutKey, fields []FieldSpec, pack int, resolve LayoutResolver) TypeLayout {
	tl := TypeLayout{Key: key, Name: key.Type, Kind: "struct"}
	if len(fields) == 0 {
		tl.Unknown = "no fields"
		return tl
	}
	offset := 0
	structAlign := 1
	for _, fs := range fields {
		size, align, ok := fieldSizeAlign(abi, fs, resolve)
		if !ok {
			tl.Unknown = "unresolvable field: " + fs.Name + " (" + fs.TypeSpelling + ")"
			return tl
		}
		effectiveAlign := align
		if pack > 0 && pack < effectiveAlign {
			effectiveAlign = pack
		}
		if fs.Pack > 0 && fs.Pack < effectiveAlign {
			effectiveAlign = fs.Pack
		}
		offset = alignUp(offset, effectiveAlign)
		tl.Fields = append(tl.Fields, FieldLayout{
			Name:       fs.Name,
			Offset:     offset,
			Size:       size,
			Align:      align,
			ArrayCount: fs.ArrayCount,
			BitWidth:   fs.BitWidth,
			IsPointer:  fs.IsPointer || IsPointerSpelling(fs.TypeSpelling),
			IsArray:    fs.IsArray,
		})
		offset += size
		if effectiveAlign > structAlign {
			structAlign = effectiveAlign
		}
	}
	tl.Align = structAlign
	tl.Size = alignUp(offset, structAlign)
	return tl
}

// LayoutUnion 计算 union 布局：size = max(fieldSize)，align = max(fieldAlign)。
// 任一字段无法解析 → unknown。
func LayoutUnion(abi ABI, key LayoutKey, fields []FieldSpec, resolve LayoutResolver) TypeLayout {
	tl := TypeLayout{Key: key, Name: key.Type, Kind: "union"}
	if len(fields) == 0 {
		tl.Unknown = "no fields"
		return tl
	}
	maxSize := 0
	maxAlign := 1
	for _, fs := range fields {
		size, align, ok := fieldSizeAlign(abi, fs, resolve)
		if !ok {
			tl.Unknown = "unresolvable field: " + fs.Name + " (" + fs.TypeSpelling + ")"
			return tl
		}
		if size > maxSize {
			maxSize = size
		}
		if align > maxAlign {
			maxAlign = align
		}
		tl.Fields = append(tl.Fields, FieldLayout{
			Name:       fs.Name,
			Offset:     0,
			Size:       size,
			Align:      align,
			ArrayCount: fs.ArrayCount,
			BitWidth:   fs.BitWidth,
			IsPointer:  fs.IsPointer || IsPointerSpelling(fs.TypeSpelling),
			IsArray:    fs.IsArray,
		})
	}
	// sizeof(union) rounds the largest member up to the union's alignment
	// (`union { long long x; char b[9]; }` is 16, not 9); otherwise a containing
	// struct's following offsets are undersized.
	tl.Size = alignUp(maxSize, maxAlign)
	tl.Align = maxAlign
	return tl
}

// LayoutPointer 返回指针类型的布局。
func LayoutPointer(abi ABI, key LayoutKey) TypeLayout {
	return TypeLayout{
		Key:   key,
		Name:  key.Type,
		Kind:  "pointer",
		Size:  PointerBits(abi) / 8,
		Align: PointerAlign(abi),
	}
}

// LayoutArray 返回数组类型的布局：size = count * elemSize，align = elemAlign。
// elemSize 未知或 count<=0 → unknown。
func LayoutArray(abi ABI, key LayoutKey, elemSpelling string, count int, resolve LayoutResolver) TypeLayout {
	tl := TypeLayout{Key: key, Name: key.Type, Kind: "array"}
	if count <= 0 {
		tl.Unknown = "unknown array count"
		return tl
	}
	elemSize, elemAlign, ok := fieldSizeAlign(abi, FieldSpec{TypeSpelling: elemSpelling}, resolve)
	if !ok {
		tl.Unknown = "unknown element size: " + elemSpelling
		return tl
	}
	tl.Size = elemSize * count
	tl.Align = elemAlign
	return tl
}

// IsUnknown 报告该 layout 是否不可用（Unknown 非空）。
func (t TypeLayout) IsUnknown() bool { return t.Unknown != "" }

// CanConfirm 报告该 layout 是否允许 confirmed 结论：
// provenance 可信 且 非 unknown 且 size>0。
func (t TypeLayout) CanConfirm() bool {
	return t.Provenance.CanConfirm() && !t.IsUnknown() && t.Size > 0
}

// FieldByName 查询 struct/union 的字段布局。
func (t TypeLayout) FieldByName(name string) (FieldLayout, bool) {
	for i := range t.Fields {
		if t.Fields[i].Name == name {
			return t.Fields[i], true
		}
	}
	return FieldLayout{}, false
}
