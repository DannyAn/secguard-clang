package evidence

import (
	"testing"
)

func TestIntegerOverflow_SizeCalc(t *testing.T) {
	store := runIndexAndDetect(t, "tc25_integer_overflow.c")
	assertHasEvent(t, store, "INTEGER_OVERFLOW", "integer_overflow")
}

func TestRaceCondition_TOCTOU(t *testing.T) {
	store := runIndexAndDetect(t, "tc26_toctou.c")
	assertHasEvent(t, store, "RACE_CONDITION", "toctou")
}

func TestHardcodedSecret_Password(t *testing.T) {
	store := runIndexAndDetect(t, "tc27_hardcoded_secret.c")
	assertHasEvent(t, store, "HARDCODED_SECRET", "hardcoded_secret")
}

func TestDeadlock_LockOrderInversion(t *testing.T) {
	store := runIndexAndDetect(t, "tc28_deadlock.c")
	assertHasEvent(t, store, "DEADLOCK", "deadlock")
}

func TestCryptoMisuse_WeakPRNG(t *testing.T) {
	store := runIndexAndDetect(t, "tc29_crypto_misuse.c")
	assertHasEvent(t, store, "CRYPTO_MISUSE", "crypto_misuse")
}
