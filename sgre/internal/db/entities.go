package db

type File struct {
	ID        int64
	Path      string
	Language  string
	Checksum  string
	LOC       int
	CreatedAt int64
}

type Function struct {
	ID         int64
	FileID     int64
	Name       string
	Signature  string
	ReturnType string
	IsStatic   bool
	StartLine  int
	EndLine    int
}

type Variable struct {
	ID              int64
	FunctionID      int64
	Name            string
	Type            string
	StorageClass    string
	DeclarationLine int
	IsPointer       bool
	IsNullable      bool
	SourceKind      string
}

type Expression struct {
	ID         int64
	FunctionID int64
	Text       string
	Line       int
	ExprType   string
}

type Type struct {
	ID   int64
	Name string
	Kind string
}

type Location struct {
	ID     int64
	FileID int64
	Line   int
	Column int
}

type GraphNode struct {
	ID         int64
	EntityType string
	EntityID   int64
	Properties string
}

type GraphEdge struct {
	ID         int64
	SrcID      int64
	DstID      int64
	EdgeType   string
	Properties string
}

type SecurityEvent struct {
	ID         int64
	EventType  string
	EntityID   int64
	LocationID int64
	Properties string
}

type Finding struct {
	ID           int64   `json:"id"`
	RuleID       string  `json:"rule_id"`
	Severity     string  `json:"severity"`
	Confidence   float64 `json:"confidence"`
	Evidence     string  `json:"evidence"`
	Status       string  `json:"status"`
	FilePath     string  `json:"file_path"`
	LineNumber   int     `json:"line_number"`
	FunctionName string  `json:"function_name"`
	Properties   string  `json:"properties,omitempty"`
	ScanID       string  `json:"scan_id,omitempty"`
	CreatedAt    int64   `json:"created_at"`
}

type ScanStat struct {
	ID          int64  `json:"id"`
	ScanID      string `json:"scan_id"`
	VulnType    string `json:"vuln_type"`
	SeedCount   int    `json:"seed_count"`
	FinalCount  int    `json:"final_count"`
	FilterChain string `json:"filter_chain"`
	CreatedAt   int64  `json:"created_at"`
}

type FunctionSummary struct {
	FunctionID        int64
	ReturnNullable    bool
	ParameterNullable string
	SideEffect        string
	SummaryJSON       string
}
