package planner

import (
	"github.com/DannyAn/secguard-clang/internal/db"
	"github.com/DannyAn/secguard-clang/internal/graph"
	"github.com/DannyAn/secguard-clang/internal/log"
	"github.com/DannyAn/secguard-clang/internal/parser"
)

// FilterDeps carries every collaborator a Filter constructor may need. It is
// the single struct Planner passes to FilterFactory functions so adding a
// shared resource (a new cache, a config handle) does not force a signature
// change on all 13 filter-construction sites.
type FilterDeps struct {
	Store          db.Store
	Parser         *parser.Parser
	Logger         *log.Logger
	CallReachCache *callReachCache
	TaintCache     *taintSummaryCache
	Macro          *macroContextDetector
	CFGCache       *graph.CFGCache
}

// FilterFactory constructs one Filter given the Planner's shared deps.
// Factories live on VulnTypeSpec.FilterFactories so a vuln type declares its
// chain next to the rest of its metadata instead of a switch arm in
// planner.go.
type FilterFactory func(deps FilterDeps) Filter

// buildFilters instantiates the filters for spec. When spec.FilterFactories
// is non-empty it is authoritative; otherwise we fall back to the legacy
// string-keyed switch (kept during the migration window).
func (p *Planner) buildFilters(spec *VulnTypeSpec) ([]Filter, error) {
	if len(spec.FilterFactories) == 0 {
		return p.getFilters(spec.FilterChain)
	}
	deps := FilterDeps{
		Store:          p.store,
		Parser:         p.parser,
		Logger:         p.logger,
		CallReachCache: p.callReachCache,
		TaintCache:     p.taintCache,
		Macro:          p.macro,
		CFGCache:       p.cfgCache,
	}
	out := make([]Filter, 0, len(spec.FilterFactories))
	for _, f := range spec.FilterFactories {
		out = append(out, f(deps))
	}
	return out, nil
}

// chainDefault is the default two-filter chain (call-reach + safe-function).
func chainDefault() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
	}
}

func chainNullDeref() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewTypeExprFilter() },
		func(d FilterDeps) Filter { return NewNonNullableFilter() },
		func(d FilterDeps) Filter { return NewArrayOOBPrecedenceFilter(d.Store) },
		func(d FilterDeps) Filter { return NewNullableSourceFilter(d.Store).WithParser(d.Parser, d.Logger) },
		func(d FilterDeps) Filter { return NewMacroUncertainFilter(d.Store, d.Macro) },
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
	}
}

func chainMemoryLeak() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewReleaseFilter(d.Store, "MEMORY_RELEASE") },
		func(d FilterDeps) Filter { return NewOwnershipTransferFilter(d.Store) },
		func(d FilterDeps) Filter { return NewLeakProofFilter(d.Store, "MEMORY_ALLOC") },
	}
}

func chainBufferOverflow() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewRangeOOBFilter(d.Store, d.Parser, d.Logger) },
	}
}

func chainResourceLeak() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewReleaseFilter(d.Store, "RESOURCE_RELEASE") },
		func(d FilterDeps) Filter { return NewOwnershipTransferFilter(d.Store) },
		func(d FilterDeps) Filter { return NewLeakProofFilter(d.Store, "RESOURCE_ACQUIRE") },
	}
}

func chainLifetime() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewLifetimeFilter(d.Store, d.Parser, d.Logger) },
	}
}

func chainUninit() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewDefiniteInitFilter(d.Store, d.Parser, d.Logger) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
	}
}

func chainDoubleFree() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewDoubleFreeFilter(d.Store, d.Parser, d.Logger) },
	}
}

// chainTaint covers injection / path-traversal / format-string, which share
// the taint-source filter.
func chainTaint() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewTaintSourceFilter(d.Store, d.Parser, d.Logger, d.TaintCache) },
	}
}

func chainIntegerOverflow() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewIntOverflowGuardFilter(d.Store, d.Parser, d.Logger) },
		func(d FilterDeps) Filter { return NewUnsignedSubGuardFilter(d.Store, d.Parser, d.Logger) },
	}
}

func chainDivideByZero() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewRangeFilter(d.Store, d.Parser, d.Logger) },
	}
}

func chainDeadlock() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewLockOrderFilter(d.Store, d.Parser, d.Logger) },
	}
}

func chainRaceCondition() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewSharedAccessFilter(d.Store, d.Parser, d.Logger) },
	}
}

func chainUncheckedReturn() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewReturnCheckFilter(d.Store, d.Parser, d.Logger) },
	}
}

func chainHardcodedSecret() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewHardcodedSecretProofFilter(d.Store) },
	}
}

func chainImplicitContract() []FilterFactory {
	return []FilterFactory{
		func(d FilterDeps) Filter { return NewCallReachFilter(d.Store, d.CallReachCache) },
		func(d FilterDeps) Filter { return NewSafeFunctionFilter(d.Store) },
		func(d FilterDeps) Filter { return NewContractGapFilter(d.Store).WithParser(d.Parser, d.Logger) },
	}
}

// filterFactoriesFor maps a legacy FilterChain string to its declarative
// factories. It exists so the migration to spec.FilterFactories can be done
// one type at a time while the legacy switch is still the fallback.
func filterFactoriesFor(chain string) []FilterFactory {
	switch chain {
	case "default":
		return chainDefault()
	case "null-deref":
		return chainNullDeref()
	case "memory-leak":
		return chainMemoryLeak()
	case "buffer-overflow":
		return chainBufferOverflow()
	case "resource-leak":
		return chainResourceLeak()
	case "lifetime":
		return chainLifetime()
	case "uninit":
		return chainUninit()
	case "double-free":
		return chainDoubleFree()
	case "injection", "path-traversal", "format-string":
		return chainTaint()
	case "integer-overflow":
		return chainIntegerOverflow()
	case "divide-by-zero":
		return chainDivideByZero()
	case "deadlock":
		return chainDeadlock()
	case "race-condition":
		return chainRaceCondition()
	case "unchecked-return":
		return chainUncheckedReturn()
	case "hardcoded-secret":
		return chainHardcodedSecret()
	case "implicit-contract":
		return chainImplicitContract()
	}
	return nil
}
