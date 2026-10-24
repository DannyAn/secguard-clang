package planner

// CommonCandidate is a typed read-only view of the Candidate fields that are
// shared across most or all vulnerability types. Candidate itself remains a
// flat struct (so existing literals, tests, and JSON serialization are
// untouched); Common() produces this view on demand for consumers that only
// need the shared subset and want a smaller surface to reason about.
type CommonCandidate struct {
	DerefEventID   int64
	FunctionID     int64
	FunctionName   string
	VariableName   string
	Expression     string
	APIName        string
	Category       string
	LocationID     int64
	FileID         int64
	Line           int
	SuspicionLevel string
	QualityScore   float64
	MacroContext   bool
	// Function context.
	FunctionSignature string
	FuncStartLine     int
	FuncEndLine       int
	// Source context.
	SourceLine int
	DeclLine   int
	Origin     string
	FieldPath  string
	DerefLines []int
	// Callee context (unchecked-return / null-deref call-result).
	CalleeName         string
	IsCallResultDeref  bool
	CalleeDefFile      string
	CalleeDefLine      int
	CalleeDefEndLine   int
	CalleeDefSignature string
	ContractKnown      bool
	Consumed           string
	// Null-deref specific.
	NullOriginTier     string
	NullableOriginName string
	CallerNullDetail   string
	DerivedFrom        string
	NonNullable        bool
	IsTypeExpr         bool
	// Legacy bool flags (kept for compatibility with Candidate's serialized form).
	HasNullableSource bool
	HasDefiniteNull   bool
	IsReachable       bool
	HasDataFlow       bool
	HasTaintSource    bool
	IsGuarded         bool
	GuardStrength     string
	// Uninit / argument-type / data-representation (small shared groups).
	InitWrite     string
	InitWriteLine int
	ExpectedType  string
	ActualType    string
	CastType      string
}

// Common returns the CommonCandidate view of c. It is a snapshot: mutating
// the returned value does NOT affect c. Consumers that need only the shared
// fields should prefer this over touching Candidate's 70+ fields directly.
func (c Candidate) Common() CommonCandidate {
	return CommonCandidate{
		DerefEventID:   c.DerefEventID,
		FunctionID:     c.FunctionID,
		FunctionName:   c.FunctionName,
		VariableName:   c.VariableName,
		Expression:     c.Expression,
		APIName:        c.APIName,
		Category:       c.Category,
		LocationID:     c.LocationID,
		FileID:         c.FileID,
		Line:           c.Line,
		SuspicionLevel: c.SuspicionLevel,
		QualityScore:   c.QualityScore,
		MacroContext:   c.MacroContext,

		FunctionSignature: c.FunctionSignature,
		FuncStartLine:     c.FuncStartLine,
		FuncEndLine:       c.FuncEndLine,

		SourceLine: c.SourceLine,
		DeclLine:   c.DeclLine,
		Origin:     c.Origin,
		FieldPath:  c.FieldPath,
		DerefLines: c.DerefLines,

		CalleeName:         c.CalleeName,
		IsCallResultDeref:  c.IsCallResultDeref,
		CalleeDefFile:      c.CalleeDefFile,
		CalleeDefLine:      c.CalleeDefLine,
		CalleeDefEndLine:   c.CalleeDefEndLine,
		CalleeDefSignature: c.CalleeDefSignature,
		ContractKnown:      c.ContractKnown,
		Consumed:           c.Consumed,

		NullOriginTier:     c.NullOriginTier,
		NullableOriginName: c.NullableOriginName,
		CallerNullDetail:   c.CallerNullDetail,
		DerivedFrom:        c.DerivedFrom,
		NonNullable:        c.NonNullable,
		IsTypeExpr:         c.IsTypeExpr,

		HasNullableSource: c.HasNullableSource,
		HasDefiniteNull:   c.HasDefiniteNull,
		IsReachable:       c.IsReachable,
		HasDataFlow:       c.HasDataFlow,
		HasTaintSource:    c.HasTaintSource,
		IsGuarded:         c.IsGuarded,
		GuardStrength:     c.GuardStrength,

		InitWrite:     c.InitWrite,
		InitWriteLine: c.InitWriteLine,
		ExpectedType:  c.ExpectedType,
		ActualType:    c.ActualType,
		CastType:      c.CastType,
	}
}

// LeakPayload is the typed view of the Candidate fields specific to
// memory-leak / resource-leak.
type LeakPayload struct {
	DefiniteLeak            bool
	LeakEscapeKind          string
	LeakFreeLines           string
	LeakFreeMismatch        string
	LeakTransferConditional string
	LeakFreeOnBorrow        string
}

// Leak returns the leak-specific view of c.
func (c Candidate) Leak() LeakPayload {
	return LeakPayload{
		DefiniteLeak:            c.DefiniteLeak,
		LeakEscapeKind:          c.LeakEscapeKind,
		LeakFreeLines:           c.LeakFreeLines,
		LeakFreeMismatch:        c.LeakFreeMismatch,
		LeakTransferConditional: c.LeakTransferConditional,
		LeakFreeOnBorrow:        c.LeakFreeOnBorrow,
	}
}

// FreePayload is the typed view of the Candidate fields specific to
// use-after-free / double-free.
type FreePayload struct {
	FreeLine     int
	FirstFree    int
	SecondFree   int
	MayFree      bool
	FirstCallee  string
	SecondCallee string
	Victims      string
}

// Free returns the free-specific view of c.
func (c Candidate) Free() FreePayload {
	return FreePayload{
		FreeLine:     c.FreeLine,
		FirstFree:    c.FirstFree,
		SecondFree:   c.SecondFree,
		MayFree:      c.MayFree,
		FirstCallee:  c.FirstCallee,
		SecondCallee: c.SecondCallee,
		Victims:      c.Victims,
	}
}

// BufferPayload is the typed view of the Candidate fields specific to
// buffer-overflow / out-of-bounds.
type BufferPayload struct {
	Array          string
	Index          string
	Size           int
	IndexSource    string
	CapacitySymbol string
	ElemField      string
	Escape         string
	EscapeDeref    string
	SrcCapacity    int
	CopySize       string
	DstCapacity    string
	SizeArgument   string
}

// Buffer returns the buffer-specific view of c.
func (c Candidate) Buffer() BufferPayload {
	return BufferPayload{
		Array:          c.Array,
		Index:          c.Index,
		Size:           c.Size,
		IndexSource:    c.IndexSource,
		CapacitySymbol: c.CapacitySymbol,
		ElemField:      c.ElemField,
		Escape:         c.Escape,
		EscapeDeref:    c.EscapeDeref,
		SrcCapacity:    c.SrcCapacity,
		CopySize:       c.CopySize,
		DstCapacity:    c.DstCapacity,
		SizeArgument:   c.SizeArgument,
	}
}

// IntOverflowPayload is the typed view of the integer-overflow fields.
type IntOverflowPayload struct {
	LHSKind          string
	RHSKind          string
	SubLHSInfluenced bool
	SubRHSInfluenced bool
	SubSink          string
}

// IntOverflow returns the integer-overflow-specific view of c.
func (c Candidate) IntOverflow() IntOverflowPayload {
	return IntOverflowPayload{
		LHSKind:          c.LHSKind,
		RHSKind:          c.RHSKind,
		SubLHSInfluenced: c.SubLHSInfluenced,
		SubRHSInfluenced: c.SubRHSInfluenced,
		SubSink:          c.SubSink,
	}
}

// RacePayload is the typed view of the race-condition / deadlock / TOCTOU
// fields.
type RacePayload struct {
	ThreadFunctions string
	ThreadInstances int
	WriteLine       int
	MutexA          string
	MutexB          string
	ReverseFunc     string
	CheckFunction   string
	UseFunction     string
	CheckPathArg    string
	Mutex           string
	LockLine        int
	UnlockLine      int
}

// Race returns the race-specific view of c.
func (c Candidate) Race() RacePayload {
	return RacePayload{
		ThreadFunctions: c.ThreadFunctions,
		ThreadInstances: c.ThreadInstances,
		WriteLine:       c.WriteLine,
		MutexA:          c.MutexA,
		MutexB:          c.MutexB,
		ReverseFunc:     c.ReverseFunc,
		CheckFunction:   c.CheckFunction,
		UseFunction:     c.UseFunction,
		CheckPathArg:    c.CheckPathArg,
		Mutex:           c.Mutex,
		LockLine:        c.LockLine,
		UnlockLine:      c.UnlockLine,
	}
}

// DivisorPayload is the typed view of the divide-by-zero fields.
type DivisorPayload struct {
	DivisorInterval string
	DivisorCallers  string
}

// Divisor returns the divide-by-zero-specific view of c.
func (c Candidate) Divisor() DivisorPayload {
	return DivisorPayload{
		DivisorInterval: c.DivisorInterval,
		DivisorCallers:  c.DivisorCallers,
	}
}

// ContractPayload is the typed view of the implicit-contract fields.
type ContractPayload struct {
	Subject      string
	CountField   string
	UseLine      int
	Missing      string
	EvidenceKind string
	GuardLine    int
}

// Contract returns the implicit-contract-specific view of c.
func (c Candidate) Contract() ContractPayload {
	return ContractPayload{
		Subject:      c.Subject,
		CountField:   c.CountField,
		UseLine:      c.UseLine,
		Missing:      c.Missing,
		EvidenceKind: c.EvidenceKind,
		GuardLine:    c.GuardLine,
	}
}
