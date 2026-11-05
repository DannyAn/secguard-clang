package typeinfo

// Provenance 标注一个 TypeLayout 事实的来源与可信度（评审 P0-1）。
//
// 仅 compiler_proven / derived_from_complete_config 且证据完整时才允许
// confirmed；assumed_default_abi / unknown 必须 fail-open（suspected 或不报）。
type Provenance string

const (
	ProvenanceCompilerProven        Provenance = "compiler_proven"
	ProvenanceDerivedFromFullConfig Provenance = "derived_from_complete_config"
	ProvenanceAssumedDefaultABI     Provenance = "assumed_default_abi"
	ProvenanceUnknown               Provenance = "unknown"
)

// CanConfirm 报告该 provenance 档位是否允许 confirmed 结论。
func (p Provenance) CanConfirm() bool {
	switch p {
	case ProvenanceCompilerProven, ProvenanceDerivedFromFullConfig:
		return true
	}
	return false
}

func (p Provenance) String() string { return string(p) }
