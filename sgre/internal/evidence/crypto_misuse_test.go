package evidence

import "testing"

func TestIsKeyName(t *testing.T) {
	keyLike := []string{"key", "Key", "aes_key", "key_schedule", "encryption_key", "master_key", "g_key"}
	for _, name := range keyLike {
		if !isKeyName(name) {
			t.Errorf("isKeyName(%q) = false, want true", name)
		}
	}
	notKey := []string{"keyboard", "keyboard_layout", "monkey", "turkey", "hockey", "g_turkey", "keylen", "keypad"}
	for _, name := range notKey {
		if isKeyName(name) {
			t.Errorf("isKeyName(%q) = true, want false (substring 'key' is not a key name)", name)
		}
	}
}
