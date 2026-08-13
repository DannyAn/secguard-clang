package evidence

import (
	"testing"
)

func TestIntegerOverflow_SizeCalc(t *testing.T) {
	store := runIndexAndDetect(t, "tc25_integer_overflow.c")
	assertHasEvent(t, store, "INTEGER_OVERFLOW", "integer_overflow")
}

func TestIntegerOverflow_SizeCalcMalloc(t *testing.T) {
	store := runIndexAndDetect(t, "tc30_size_calc_overflow.c")
	assertHasEvent(t, store, "INTEGER_OVERFLOW", "tc30_size_calc_overflow")
}

func TestArrayOOB_VariableIndexNotFlagged(t *testing.T) {
	store := runIndexAndDetect(t, "tc32_var_index_no_oob.c")
	assertNoEvent(t, store, "BUFFER_ACCESS", "tc32_var_index_no_oob")
}

func TestBufferOverflow_ConstantStrCpySafe(t *testing.T) {
	// strcpy(malloc(256), "temporary") is provably safe (10 bytes into 256),
	// so the constant-source suppression must drop it.
	store := runIndexAndDetect(t, "tc33_const_strcpy_safe.c")
	assertNoEvent(t, store, "BUFFER_ACCESS", "tc33_const_strcpy_safe")
}

func TestBufferOverflow_ConstantStrCpyUnknownSize(t *testing.T) {
	// strcpy(malloc(user_size), "initialized") has an unknown destination size,
	// so it must still be flagged.
	store := runIndexAndDetect(t, "tc34_const_strcpy_unknown_size.c")
	assertHasEvent(t, store, "BUFFER_ACCESS", "tc34_const_strcpy_unknown_size")
}

func TestRaceCondition_TOCTOU(t *testing.T) {
	store := runIndexAndDetect(t, "tc26_toctou.c")
	assertHasEvent(t, store, "RACE_CONDITION", "toctou")
}

func TestHardcodedSecret_Password(t *testing.T) {
	store := runIndexAndDetect(t, "tc27_hardcoded_secret.c")
	assertHasEvent(t, store, "HARDCODED_SECRET", "hardcoded_secret")
}

func TestHardcodedSecret_RegSetValueExCast(t *testing.T) {
	store := runIndexAndDetect(t, "tc31_reg_set_value.c")
	assertHasEvent(t, store, "HARDCODED_SECRET", "tc31_reg_set_value")
}

func TestDeadlock_LockOrderInversion(t *testing.T) {
	store := runIndexAndDetect(t, "tc28_deadlock.c")
	assertHasEvent(t, store, "DEADLOCK", "deadlock")
}

func TestCryptoMisuse_WeakPRNG(t *testing.T) {
	store := runIndexAndDetect(t, "tc29_crypto_misuse.c")
	assertHasEvent(t, store, "CRYPTO_MISUSE", "crypto_misuse")
}
