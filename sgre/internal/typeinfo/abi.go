package typeinfo

// ABI 是目标 ABI 的标识。布局算法据此选择基本类型的宽度/对齐。
type ABI string

const (
	ABILP64  ABI = "lp64"
	ABIILP32 ABI = "ilp32"
	ABILLP64 ABI = "llp64"
)

type abiEntry struct {
	bits   int
	align  int
	signed bool
}

var primitiveTable = map[string]map[ABI]abiEntry{
	"char":               {ABILP64: {8, 1, true}, ABIILP32: {8, 1, true}, ABILLP64: {8, 1, true}},
	"signed char":        {ABILP64: {8, 1, true}, ABIILP32: {8, 1, true}, ABILLP64: {8, 1, true}},
	"unsigned char":      {ABILP64: {8, 1, false}, ABIILP32: {8, 1, false}, ABILLP64: {8, 1, false}},
	"_Bool":              {ABILP64: {8, 1, false}, ABIILP32: {8, 1, false}, ABILLP64: {8, 1, false}},
	"bool":               {ABILP64: {8, 1, false}, ABIILP32: {8, 1, false}, ABILLP64: {8, 1, false}},
	"short":              {ABILP64: {16, 2, true}, ABIILP32: {16, 2, true}, ABILLP64: {16, 2, true}},
	"signed short":       {ABILP64: {16, 2, true}, ABIILP32: {16, 2, true}, ABILLP64: {16, 2, true}},
	"unsigned short":     {ABILP64: {16, 2, false}, ABIILP32: {16, 2, false}, ABILLP64: {16, 2, false}},
	"short int":          {ABILP64: {16, 2, true}, ABIILP32: {16, 2, true}, ABILLP64: {16, 2, true}},
	"int":                {ABILP64: {32, 4, true}, ABIILP32: {32, 4, true}, ABILLP64: {32, 4, true}},
	"signed":             {ABILP64: {32, 4, true}, ABIILP32: {32, 4, true}, ABILLP64: {32, 4, true}},
	"signed int":         {ABILP64: {32, 4, true}, ABIILP32: {32, 4, true}, ABILLP64: {32, 4, true}},
	"unsigned":           {ABILP64: {32, 4, false}, ABIILP32: {32, 4, false}, ABILLP64: {32, 4, false}},
	"unsigned int":       {ABILP64: {32, 4, false}, ABIILP32: {32, 4, false}, ABILLP64: {32, 4, false}},
	"long":               {ABILP64: {64, 8, true}, ABIILP32: {32, 4, true}, ABILLP64: {32, 4, true}},
	"signed long":        {ABILP64: {64, 8, true}, ABIILP32: {32, 4, true}, ABILLP64: {32, 4, true}},
	"unsigned long":      {ABILP64: {64, 8, false}, ABIILP32: {32, 4, false}, ABILLP64: {32, 4, false}},
	"long int":           {ABILP64: {64, 8, true}, ABIILP32: {32, 4, true}, ABILLP64: {32, 4, true}},
	"unsigned long int":  {ABILP64: {64, 8, false}, ABIILP32: {32, 4, false}, ABILLP64: {32, 4, false}},
	"long long":          {ABILP64: {64, 8, true}, ABIILP32: {64, 8, true}, ABILLP64: {64, 8, true}},
	"signed long long":   {ABILP64: {64, 8, true}, ABIILP32: {64, 8, true}, ABILLP64: {64, 8, true}},
	"unsigned long long": {ABILP64: {64, 8, false}, ABIILP32: {64, 8, false}, ABILLP64: {64, 8, false}},
	"float":              {ABILP64: {32, 4, true}, ABIILP32: {32, 4, true}, ABILLP64: {32, 4, true}},
	"double":             {ABILP64: {64, 8, true}, ABIILP32: {64, 8, true}, ABILLP64: {64, 8, true}},
	"long double":        {ABILP64: {128, 16, true}, ABIILP32: {128, 16, true}, ABILLP64: {128, 16, true}},
	"size_t":             {ABILP64: {64, 8, false}, ABIILP32: {32, 4, false}, ABILLP64: {64, 8, false}},
	"ssize_t":            {ABILP64: {64, 8, true}, ABIILP32: {32, 4, true}, ABILLP64: {64, 8, true}},
	"ptrdiff_t":          {ABILP64: {64, 8, true}, ABIILP32: {32, 4, true}, ABILLP64: {64, 8, true}},
	"intptr_t":           {ABILP64: {64, 8, true}, ABIILP32: {32, 4, true}, ABILLP64: {64, 8, true}},
	"uintptr_t":          {ABILP64: {64, 8, false}, ABIILP32: {32, 4, false}, ABILLP64: {64, 8, false}},
	"intmax_t":           {ABILP64: {64, 8, true}, ABIILP32: {64, 8, true}, ABILLP64: {64, 8, true}},
	"uintmax_t":          {ABILP64: {64, 8, false}, ABIILP32: {64, 8, false}, ABILLP64: {64, 8, false}},
}

var fixedWidthTypes = map[string]abiEntry{
	"int8_t": {8, 1, true}, "uint8_t": {8, 1, false},
	"int16_t": {16, 2, true}, "uint16_t": {16, 2, false},
	"int32_t": {32, 4, true}, "uint32_t": {32, 4, false},
	"int64_t": {64, 8, true}, "uint64_t": {64, 8, false},
}

func pointerWidth(abi ABI) int {
	if abi == ABIILP32 {
		return 32
	}
	return 64
}

// PrimitiveBits 返回基本类型在给定 ABI 下的位宽。ok=false 表示未知拼写。
func PrimitiveBits(abi ABI, name string) (bits int, ok bool) {
	if e, found := fixedWidthTypes[name]; found {
		return e.bits, true
	}
	if abis, found := primitiveTable[name]; found {
		if e, ok2 := abis[abi]; ok2 {
			return e.bits, true
		}
	}
	return 0, false
}

// PrimitiveAlign 返回基本类型的自然对齐（字节）。ok=false 表示未知。
func PrimitiveAlign(abi ABI, name string) (align int, ok bool) {
	if e, found := fixedWidthTypes[name]; found {
		return e.align, true
	}
	if abis, found := primitiveTable[name]; found {
		if e, ok2 := abis[abi]; ok2 {
			return e.align, true
		}
	}
	return 0, false
}

// PrimitiveSignedness 返回基本类型的默认 signedness。ok=false 表示未知。
func PrimitiveSignedness(abi ABI, name string) (signed bool, ok bool) {
	if e, found := fixedWidthTypes[name]; found {
		return e.signed, true
	}
	if abis, found := primitiveTable[name]; found {
		if e, ok2 := abis[abi]; ok2 {
			return e.signed, true
		}
	}
	return false, false
}

// IsFloat 报告 name 是否是浮点类型拼写。
func IsFloat(name string) bool {
	switch name {
	case "float", "double", "long double":
		return true
	}
	return false
}

// IsPointerSpelling 报告类型拼写是否表示指针（以 * 结尾）。
func IsPointerSpelling(spelling string) bool {
	return len(spelling) > 0 && spelling[len(spelling)-1] == '*'
}

// PointerBits 返回给定 ABI 下的指针位宽。
func PointerBits(abi ABI) int { return pointerWidth(abi) }

// PointerAlign 返回给定 ABI 下的指针对齐（字节）。
func PointerAlign(abi ABI) int { return pointerWidth(abi) / 8 }

// NormalizeABI 规范化 ABI 字符串，未知值回退 LP64。
func NormalizeABI(s string) ABI {
	switch ABI(s) {
	case ABILP64, ABIILP32, ABILLP64:
		return ABI(s)
	}
	return ABILP64
}
