package secretbox

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNewFromKey(t *testing.T) {
	raw := bytes.Repeat([]byte{0x42}, 32)
	if _, err := NewFromKey(raw); err != nil {
		t.Fatalf("NewFromKey(32 bytes) unexpected error: %v", err)
	}

	for _, size := range []int{0, 16, 24, 31, 33, 64} {
		if _, err := NewFromKey(make([]byte, size)); err == nil {
			t.Errorf("NewFromKey(%d bytes) succeeded, want error", size)
		}
	}
}

func TestLoadOrCreateKeyFilePermissionsAndReload(t *testing.T) {
	t.Setenv("CERTDNS_SECRET_KEY", "")

	dir := filepath.Join(t.TempDir(), "nested", "data")
	keyPath := filepath.Join(dir, "secret.key")

	c1, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey create error: %v", err)
	}

	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("dir perm = %04o, want 0700", got)
	}

	fileInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("key file perm = %04o, want 0600", got)
	}

	rawDisk, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key file: %v", err)
	}
	if len(rawDisk) != 65 || rawDisk[64] != '\n' {
		t.Fatalf("key file length/newline invalid: len=%d", len(rawDisk))
	}
	hexStr := string(rawDisk[:64])
	if hexStr != strings.ToLower(hexStr) {
		t.Errorf("key file hex is not lowercase: %q", hexStr)
	}
	if decoded, err := hex.DecodeString(hexStr); err != nil || len(decoded) != 32 {
		t.Fatalf("key file hex decode failed: len=%d err=%v", len(decoded), err)
	}

	const aad = "dns_accounts.access_key_secret"
	ct, err := c1.Seal("secret-value-123", aad)
	if err != nil {
		t.Fatalf("Seal error: %v", err)
	}

	// Loosen permissions to verify reload tightens them without overwriting the key.
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatalf("chmod dir 0755: %v", err)
	}
	if err := os.Chmod(keyPath, 0o644); err != nil {
		t.Fatalf("chmod key 0644: %v", err)
	}

	c2, err := LoadOrCreateKey(keyPath)
	if err != nil {
		t.Fatalf("LoadOrCreateKey reload error: %v", err)
	}

	rawAfter, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("re-read key file: %v", err)
	}
	if !bytes.Equal(rawDisk, rawAfter) {
		t.Fatalf("key file was overwritten on reload")
	}

	dirInfo, err = os.Stat(dir)
	if err != nil {
		t.Fatalf("re-stat dir: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Errorf("reloaded dir perm = %04o, want 0700", got)
	}
	fileInfo, err = os.Stat(keyPath)
	if err != nil {
		t.Fatalf("re-stat key file: %v", err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Errorf("reloaded file perm = %04o, want 0600", got)
	}

	got, err := c2.Open(ct, aad)
	if err != nil {
		t.Fatalf("reloaded Open error: %v", err)
	}
	if got != "secret-value-123" {
		t.Errorf("reloaded Open = %q, want %q", got, "secret-value-123")
	}
}

func TestLoadOrCreateKeyConcurrentNeverOverwrites(t *testing.T) {
	t.Setenv("CERTDNS_SECRET_KEY", "")

	keyPath := filepath.Join(t.TempDir(), "race", "secret.key")
	const workers = 8

	start := make(chan struct{})
	ciphers := make([]*Cipher, workers)
	errs := make([]error, workers)

	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			<-start
			ciphers[idx], errs[idx] = LoadOrCreateKey(keyPath)
		}(i)
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("worker %d LoadOrCreateKey failed: %v", i, err)
		}
	}

	ct, err := ciphers[0].Seal("shared-secret", "concurrent.aad")
	if err != nil {
		t.Fatalf("worker 0 Seal failed: %v", err)
	}
	for i := 1; i < workers; i++ {
		plain, err := ciphers[i].Open(ct, "concurrent.aad")
		if err != nil {
			t.Fatalf("worker %d failed to decrypt worker 0 ciphertext: %v", i, err)
		}
		if plain != "shared-secret" {
			t.Errorf("worker %d Open = %q, want %q", i, plain, "shared-secret")
		}
	}
}

func TestLoadOrCreateKeyCorruptFileRejected(t *testing.T) {
	t.Setenv("CERTDNS_SECRET_KEY", "")

	keyPath := filepath.Join(t.TempDir(), "secret.key")
	corrupt := []byte("not-valid-64-char-hex\n")
	if err := os.WriteFile(keyPath, corrupt, 0o600); err != nil {
		t.Fatalf("write corrupt key: %v", err)
	}

	if _, err := LoadOrCreateKey(keyPath); err == nil {
		t.Fatal("LoadOrCreateKey succeeded on corrupt key file, want error")
	}

	after, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read corrupt key file: %v", err)
	}
	if !bytes.Equal(after, corrupt) {
		t.Fatalf("corrupt key file was modified: got %q", after)
	}
}

func TestLoadOrCreateKeyEnvSupportAndPassphraseRejection(t *testing.T) {
	// Include 0xfb, 0xff, 0xbf so standard base64 emits '+'/'/' while URL base64 emits '-'/'_'.
	raw := make([]byte, 32)
	raw[0], raw[1], raw[2] = 0xfb, 0xff, 0xbf
	for i := 3; i < len(raw); i++ {
		raw[i] = byte(i * 7)
	}

	ref, err := NewFromKey(raw)
	if err != nil {
		t.Fatalf("NewFromKey: %v", err)
	}
	const aad = "settings.webhook_url"
	ct, err := ref.Seal("https://oapi.dingtalk.com/robot/send?access_token=xyz", aad)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	validCases := []struct {
		name  string
		value string
	}{
		{"hex-lower", hex.EncodeToString(raw)},
		{"hex-upper-padded-ws", "  " + strings.ToUpper(hex.EncodeToString(raw)) + "\n"},
		{"base64-std", base64.StdEncoding.EncodeToString(raw)},
		{"base64-raw-std", base64.RawStdEncoding.EncodeToString(raw)},
		{"base64-url", base64.URLEncoding.EncodeToString(raw)},
		{"base64-raw-url", base64.RawURLEncoding.EncodeToString(raw)},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("CERTDNS_SECRET_KEY", tc.value)
			c, err := LoadOrCreateKey("")
			if err != nil {
				t.Fatalf("LoadOrCreateKey env %s error: %v", tc.name, err)
			}
			got, err := c.Open(ct, aad)
			if err != nil {
				t.Fatalf("Open with %s key error: %v", tc.name, err)
			}
			if got != "https://oapi.dingtalk.com/robot/send?access_token=xyz" {
				t.Errorf("Open = %q", got)
			}
		})
	}

	invalidCases := []struct {
		name  string
		value string
	}{
		{"ascii-passphrase-32-alnum", "0123456789abcdef0123456789abcdef"},
		{"ascii-passphrase-32-punct", "my-weak-32-character-passphrase!"},
		{"short-hex", "0123456789abcdef"},
		{"invalid-64-hex", strings.Repeat("z", 64)},
		{"base64-16-bytes", base64.StdEncoding.EncodeToString(make([]byte, 16))},
		{"base64-48-bytes", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, 48))},
		{"internal-space", hex.EncodeToString(raw[:16]) + " " + hex.EncodeToString(raw[16:])},
	}

	for _, tc := range invalidCases {
		t.Run("reject-"+tc.name, func(t *testing.T) {
			t.Setenv("CERTDNS_SECRET_KEY", tc.value)
			if _, err := LoadOrCreateKey(""); err == nil {
				t.Errorf("LoadOrCreateKey accepted invalid CERTDNS_SECRET_KEY (%s)", tc.name)
			}
		})
	}
}

func TestSealOpenAndEdgeCases(t *testing.T) {
	key1 := bytes.Repeat([]byte{0x11}, 32)
	key2 := bytes.Repeat([]byte{0x22}, 32)
	c1, err := NewFromKey(key1)
	if err != nil {
		t.Fatalf("NewFromKey c1: %v", err)
	}
	c2, err := NewFromKey(key2)
	if err != nil {
		t.Fatalf("NewFromKey c2: %v", err)
	}

	const aad = "dns_accounts.access_key_secret"

	// Empty plaintext / stored string.
	if got, err := c1.Seal("", aad); err != nil || got != "" {
		t.Fatalf("Seal empty = (%q, %v), want (\"\", nil)", got, err)
	}
	if got, err := c1.Open("", aad); err != nil || got != "" {
		t.Fatalf("Open empty = (%q, %v), want (\"\", nil)", got, err)
	}

	// Standard roundtrip & distinct random nonces.
	const wantPlain = "阿里云Secret-LTAI5t9xExample"
	ct1, err := c1.Seal(wantPlain, aad)
	if err != nil {
		t.Fatalf("Seal ct1: %v", err)
	}
	ct2, err := c1.Seal(wantPlain, aad)
	if err != nil {
		t.Fatalf("Seal ct2: %v", err)
	}
	if !strings.HasPrefix(ct1, Prefix) || !strings.HasPrefix(ct2, Prefix) {
		t.Fatalf("missing Prefix: ct1=%q ct2=%q", ct1, ct2)
	}
	if ct1 == ct2 {
		t.Fatalf("two Seal calls produced identical ciphertext: %q", ct1)
	}
	if got, err := c1.Open(ct1, aad); err != nil || got != wantPlain {
		t.Fatalf("Open ct1 = (%q, %v), want (%q, nil)", got, err, wantPlain)
	}
	if got, err := c1.Open(ct2, aad); err != nil || got != wantPlain {
		t.Fatalf("Open ct2 = (%q, %v), want (%q, nil)", got, err, wantPlain)
	}

	// Empty AAD roundtrip.
	ctNoAAD, err := c1.Seal("no-aad-value", "")
	if err != nil {
		t.Fatalf("Seal empty AAD: %v", err)
	}
	if got, err := c1.Open(ctNoAAD, ""); err != nil || got != "no-aad-value" {
		t.Fatalf("Open empty AAD = (%q, %v)", got, err)
	}

	// AAD mismatch & wrong key rejection.
	if _, err := c1.Open(ct1, "settings.webhook_url"); err == nil {
		t.Error("Open with mismatched AAD succeeded, want error")
	}
	if _, err := c1.Open(ct1, ""); err == nil {
		t.Error("Open with empty AAD on AAD-bound ciphertext succeeded, want error")
	}
	if _, err := c2.Open(ct1, aad); err == nil {
		t.Error("Open with wrong key succeeded, want error")
	}

	// Non-passthrough when plain already starts with Prefix (cross-field oracle defense).
	prefixedInput := Prefix + "attacker-injected-token"
	doubleSealed, err := c1.Seal(prefixedInput, aad)
	if err != nil {
		t.Fatalf("Seal prefixed input: %v", err)
	}
	if doubleSealed == prefixedInput {
		t.Fatal("Seal passed through Prefix-prefixed input without encrypting")
	}
	if got, err := c1.Open(doubleSealed, aad); err != nil || got != prefixedInput {
		t.Fatalf("Open doubleSealed = (%q, %v), want (%q, nil)", got, err, prefixedInput)
	}

	nestedCT, err := c1.Seal(ct1, "other.field")
	if err != nil {
		t.Fatalf("Seal nested ciphertext: %v", err)
	}
	if nestedCT == ct1 {
		t.Fatal("Seal passed through existing ciphertext unchanged")
	}
	if got, err := c1.Open(nestedCT, "other.field"); err != nil || got != ct1 {
		t.Fatalf("Open nestedCT = (%q, %v), want original ct1", got, err)
	}

	// Legacy unencrypted plaintext passthrough in Open.
	const legacyPlain = "legacy-plaintext-secret-without-prefix"
	if got, err := c1.Open(legacyPlain, aad); err != nil || got != legacyPlain {
		t.Fatalf("Open legacy plaintext = (%q, %v), want (%q, nil)", got, err, legacyPlain)
	}

	// nil Cipher behavior.
	var nilCipher *Cipher
	if got, err := nilCipher.Seal("raw-secret", aad); err != nil || got != "raw-secret" {
		t.Fatalf("nil Seal = (%q, %v), want (\"raw-secret\", nil)", got, err)
	}
	if got, err := nilCipher.Seal("", aad); err != nil || got != "" {
		t.Fatalf("nil Seal empty = (%q, %v), want (\"\", nil)", got, err)
	}
	if got, err := nilCipher.Open("", aad); err != nil || got != "" {
		t.Fatalf("nil Open empty = (%q, %v), want (\"\", nil)", got, err)
	}
	if got, err := nilCipher.Open("legacy-plain", aad); err != nil || got != "legacy-plain" {
		t.Fatalf("nil Open legacy = (%q, %v), want (\"legacy-plain\", nil)", got, err)
	}
	if _, err := nilCipher.Open(ct1, aad); err == nil {
		t.Error("nil Open on encrypted value succeeded, want error")
	}
	if _, err := nilCipher.Open(Prefix+"anything", aad); err == nil {
		t.Error("nil Open on Prefix value succeeded, want error")
	}

	// Truncated and corrupt ciphertexts.
	rawCT, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(ct1, Prefix))
	if err != nil {
		t.Fatalf("decode ct1 payload: %v", err)
	}
	tamperedNonce := append([]byte(nil), rawCT...)
	tamperedNonce[0] ^= 0xff
	tamperedTag := append([]byte(nil), rawCT...)
	tamperedTag[len(tamperedTag)-1] ^= 0xff

	corruptInputs := []struct {
		name string
		val  string
	}{
		{"prefix-only", Prefix},
		{"bad-base64", Prefix + "!!!not_base64!!!"},
		{"padded-base64", Prefix + base64.StdEncoding.EncodeToString(rawCT)},
		{"short-12-bytes", Prefix + base64.RawStdEncoding.EncodeToString(make([]byte, 12))},
		{"short-27-bytes", Prefix + base64.RawStdEncoding.EncodeToString(make([]byte, 27))},
		{"tampered-nonce", Prefix + base64.RawStdEncoding.EncodeToString(tamperedNonce)},
		{"tampered-tag", Prefix + base64.RawStdEncoding.EncodeToString(tamperedTag)},
	}

	for _, tc := range corruptInputs {
		if _, err := c1.Open(tc.val, aad); err == nil {
			t.Errorf("Open(%s) succeeded, want error", tc.name)
		}
	}
}
