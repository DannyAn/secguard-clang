package planner

import (
	"strings"
	"testing"
)

// B2 rollout: the crypto-misuse verdict basis is the detector's own rationale
// (not the API name) plus the declared key size — both were computed by the
// filter but never reached the classifier as facts.
func TestBuildVerdictFacts_CryptoMisuse(t *testing.T) {
	spec, err := GetVulnTypeSpec("crypto-misuse")
	if err != nil {
		t.Fatal(err)
	}
	facts := spec.BuildVerdictFacts(Candidate{CryptoReason: "DES is weak (56-bit key)", CryptoKeySize: 7, Line: 12, Category: "undersized_key"})
	if len(facts) != 2 {
		t.Fatalf("facts = %d, want 2 (reason + key size): %+v", len(facts), facts)
	}
	if facts[0].Token != "reason@DES is weak (56-bit key)" {
		t.Errorf("reason token = %q", facts[0].Token)
	}
	if !strings.Contains(facts[0].Detail, "line 12") || !strings.Contains(facts[0].Detail, "regardless of call context") {
		t.Errorf("reason detail must name the line and that the primitive itself is broken:\n%s", facts[0].Detail)
	}
	if facts[1].Token != "key-size@7" {
		t.Errorf("key-size token = %q", facts[1].Token)
	}
	if !strings.Contains(facts[1].Detail, "7 bytes") || !strings.Contains(facts[1].Detail, "128 bits") {
		t.Errorf("key-size detail must state the size and the minimum:\n%s", facts[1].Detail)
	}

	bare := spec.BuildVerdictFacts(Candidate{Line: 3})
	if len(bare) != 0 {
		t.Errorf("no reason / key size: facts must be empty, got %+v", bare)
	}
}

// B2 rollout: the BO/OOB verdict basis is the buffer/capacity/index triple.
// A constant index or copy size that reached a candidate was detector-proved
// out-of-bounds; a variable one is what the classifier must range-judge —
// the fact detail must say which of the two it is looking at.
func TestBuildVerdictFacts_BufferOverflow(t *testing.T) {
	bo, err := GetVulnTypeSpec("buffer-overflow")
	if err != nil {
		t.Fatal(err)
	}
	oob, err := GetVulnTypeSpec("out-of-bounds")
	if err != nil {
		t.Fatal(err)
	}

	constIdx := bo.BuildVerdictFacts(Candidate{Array: "buf", Size: 16, Index: "20", Line: 9, Category: "array_oob_write"})
	if len(constIdx) != 3 {
		t.Fatalf("constant-index facts = %d, want 3 (buf/cap/idx): %+v", len(constIdx), constIdx)
	}
	if constIdx[0].Token != "buf@buf" || constIdx[1].Token != "cap@16" || constIdx[2].Token != "idx@20" {
		t.Errorf("token sequence = %q %q %q", constIdx[0].Token, constIdx[1].Token, constIdx[2].Token)
	}
	if !strings.Contains(constIdx[2].Detail, "machine-proved") {
		t.Errorf("constant idx fact must say the detector already proved it:\n%s", constIdx[2].Detail)
	}

	varCopy := bo.BuildVerdictFacts(Candidate{Array: "dst", Size: 64, CopySize: "n", Line: 30, Category: "bounded_copy_var_size"})
	if len(varCopy) != 3 || varCopy[2].Token != "idx@n" {
		t.Fatalf("variable-copy facts = %+v", varCopy)
	}
	if !strings.Contains(varCopy[2].Detail, "reachable range") || !strings.Contains(varCopy[2].Detail, "caller-influenced") {
		t.Errorf("variable idx fact must direct the range judgment:\n%s", varCopy[2].Detail)
	}

	read := oob.BuildVerdictFacts(Candidate{Array: "data", Size: 8, Index: "12", Line: 41, Category: "array_oob_read"})
	if len(read) != 3 || read[0].Token != "buf@data" || read[2].Token != "idx@12" {
		t.Errorf("out-of-bounds shares the buffer builder: %+v", read)
	}

	// F1: the Annex-K paths surface their declared size argument through idx@
	// (the value the function trusts / requires), so the secure_* categories
	// get the same triple as the bounded-copy ones.
	secureLie := bo.BuildVerdictFacts(Candidate{Array: "dst", Size: 64, SizeArgument: "128", Line: 22, Category: "secure_copy_overflow"})
	if len(secureLie) != 3 || secureLie[2].Token != "idx@128" {
		t.Fatalf("secure lying-capacity facts = %+v", secureLie)
	}
	if !strings.Contains(secureLie[2].Detail, "machine-proved") {
		t.Errorf("a declared 128 against cap@64 is detector-proved; the detail must say so:\n%s", secureLie[2].Detail)
	}

	secureVar := bo.BuildVerdictFacts(Candidate{Array: "dst", Size: 64, SizeArgument: "n", Line: 25, Category: "secure_copy_var_size"})
	if len(secureVar) != 3 || secureVar[2].Token != "idx@n" {
		t.Fatalf("secure variable-size facts = %+v", secureVar)
	}
	if !strings.Contains(secureVar[2].Detail, "reachable range") {
		t.Errorf("variable declared size needs the range judgment:\n%s", secureVar[2].Detail)
	}

	compact := bo.BuildVerdictFacts(Candidate{Array: "dst", Size: 64, CopySize: "n + 1", Line: 28, Category: "bounded_copy_var_size"})
	if len(compact) != 3 || compact[2].Token != "idx@n+1" {
		t.Errorf("a spaced copy-size expression must be whitespace-compacted into one token: %+v", compact)
	}

	bare := bo.BuildVerdictFacts(Candidate{Line: 5})
	if len(bare) != 0 {
		t.Errorf("no buffer facts: facts must be empty, got %+v", bare)
	}
}
