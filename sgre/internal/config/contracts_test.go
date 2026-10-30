package config

import (
	"testing"

	"github.com/BurntSushi/toml"
)

func TestContractsParsing(t *testing.T) {
	data := `
[contracts]
"framework_send_data" = { takes_ownership = "param-1", releases = "on-success" }
"vendor_hton_buf" = { out_params = ["param-4"] }
"legacy_note" = "manual contract"
`
	cfg := &Config{}
	if err := toml.Unmarshal([]byte(data), cfg); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	bySym := cfg.ContractBySymbol()
	if len(bySym) != 3 {
		t.Fatalf("got %d contracts, want 3: %+v", len(bySym), bySym)
	}

	fw := bySym["framework_send_data"]
	if fw.TakesOwnership != "param-1" || fw.Releases != "on-success" {
		t.Errorf("framework contract wrong: %+v", fw)
	}

	vv := bySym["vendor_hton_buf"]
	if len(vv.OutParams) != 1 || vv.OutParams[0] != "param-4" {
		t.Errorf("vendor contract wrong: %+v", vv)
	}

	if bySym["legacy_note"].Note != "manual contract" {
		t.Errorf("bare-string contract note wrong: %+v", bySym["legacy_note"])
	}
}

func TestContractsEmpty(t *testing.T) {
	var cfg Config
	if got := cfg.ContractBySymbol(); len(got) != 0 {
		t.Errorf("zero config must yield an empty map, got %+v", got)
	}
	if got := (*Config)(nil).ContractBySymbol(); len(got) != 0 {
		t.Errorf("nil config must yield an empty map, got %+v", got)
	}
}

func TestAIStageMode(t *testing.T) {
	var cfg Config
	if cfg.AIStageMode() != "agent" {
		t.Errorf("zero config must default to agent, got %q", cfg.AIStageMode())
	}
	cfg.AIMode = "executor"
	if cfg.AIStageMode() != "executor" {
		t.Errorf("executor not honored: %q", cfg.AIStageMode())
	}
	cfg.AIMode = "Executor"
	if cfg.AIStageMode() != "executor" {
		t.Errorf("mode must be case-insensitive: %q", cfg.AIStageMode())
	}
	if (*Config)(nil).AIStageMode() != "agent" {
		t.Errorf("nil config must default to agent")
	}
}
