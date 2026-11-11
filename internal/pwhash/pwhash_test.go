package pwhash

import (
	"encoding/hex"
	"strings"
	"testing"

	"golang.org/x/crypto/scrypt"
)

func TestHashVerifyRoundtrip(t *testing.T) {
	t.Parallel()

	const password = "correct-horse-battery"
	h1, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash returned unexpected error: %v", err)
	}
	if !strings.HasPrefix(h1, "scrypt:32768:8:1$") {
		t.Fatalf("unexpected hash prefix: %q", h1)
	}
	parts := strings.Split(h1, "$")
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts in hash, got %d: %q", len(parts), h1)
	}
	if len(parts[1]) != 16 {
		t.Fatalf("expected 16-char salt, got %d: %q", len(parts[1]), parts[1])
	}
	for _, r := range parts[1] {
		if !strings.ContainsRune(saltChars, r) {
			t.Fatalf("salt contains unexpected char %q in %q", r, parts[1])
		}
	}
	if len(parts[2]) != 128 {
		t.Fatalf("expected 128 hex chars (64 bytes), got %d", len(parts[2]))
	}

	h2, err := Hash(password)
	if err != nil {
		t.Fatalf("second Hash returned unexpected error: %v", err)
	}
	if h1 == h2 {
		t.Fatalf("expected distinct random salts across Hash calls, got identical %q", h1)
	}

	if !Verify(h1, password) {
		t.Fatal("Verify rejected valid password")
	}
	if Verify(h1, "wrong-password") {
		t.Fatal("Verify accepted wrong password")
	}
	if Verify(h1, "") {
		t.Fatal("Verify accepted empty password for non-empty hash")
	}
	if Verify(h1, "correct-horse-batterY") {
		t.Fatal("Verify accepted case-mismatched password")
	}

	emptySalt, err := salt(0)
	if err != nil || emptySalt != "" {
		t.Fatalf("salt(0) = (%q, %v), want (\"\", nil)", emptySalt, err)
	}
}

func TestVerifyCompatibleVectors(t *testing.T) {
	t.Parallel()

	const (
		pw   = "correct-horse-battery"
		s    = "werkzeugsalt1234"
		p256 = "15fdf2bf04be2a1f1b221208d4776d6f83c39eb117ce3bdf09a31451460bffe8"
	)

	boundaryKey, err := scrypt.Key([]byte(pw), []byte(s), 2, 32, 16, 16)
	if err != nil {
		t.Fatalf("scrypt.Key boundary setup failed: %v", err)
	}

	cases := []struct {
		name    string
		encoded string
	}{
		{
			name:    "pbkdf2_1_field_default_sha256_600000",
			encoded: "pbkdf2$" + s + "$" + p256,
		},
		{
			name:    "pbkdf2_2_fields_sha256_default_600000",
			encoded: "pbkdf2:sha256$" + s + "$" + p256,
		},
		{
			name:    "pbkdf2_3_fields_sha256_1000",
			encoded: "pbkdf2:sha256:1000$" + s + "$34518efc6d3cec57f908582b21a09ca8748ef126ff62f89cf5ed7020b64baaad",
		},
		{
			name:    "pbkdf2_sha512_1000",
			encoded: "pbkdf2:sha512:1000$" + s + "$ab3f0e8385d58cda6e9996f111082319448d6845b45a770bb6ed3ffe8a37e044c07b16b31f8f5c2140482f31a7e5576e7c91df5a56c183bb976e06a617c26705",
		},
		{
			name:    "pbkdf2_sha1_1000",
			encoded: "pbkdf2:sha1:1000$" + s + "$15411464860a4b0d3194d53efff038f155b4714a",
		},
		{
			name:    "pbkdf2_exact_16_byte_digest_uppercase_hex",
			encoded: "pbkdf2:sha256:1000$" + s + "$" + strings.ToUpper("34518efc6d3cec57f908582b21a09ca8"),
		},
		{
			name:    "scrypt_1_field_default_32768_8_1",
			encoded: "scrypt$" + s + "$1ccd5d13f26d814be32707449716dbcf407ead7900743d803abae4716a21de9c1dc2c11f3c20255ef45756de71e863cf01cd9a5a5c1adb8b3567ca49ab80f897",
		},
		{
			name:    "scrypt_4_fields_custom_1024_4_1",
			encoded: "scrypt:1024:4:1$" + s + "$d2a42de68d8047d80df4811f2db144bd94bf619a23205f13e1e5b5b0e6dde9f1",
		},
		{
			name:    "scrypt_4_fields_bounds_2_32_16",
			encoded: "scrypt:2:32:16$" + s + "$" + hex.EncodeToString(boundaryKey),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if !Verify(tc.encoded, pw) {
				t.Fatalf("Verify(%q) returned false for valid password", tc.encoded)
			}
			if Verify(tc.encoded, "wrong-password") {
				t.Fatalf("Verify(%q) returned true for wrong password", tc.encoded)
			}
		})
	}
}

func TestVerifyRejectsMalformedAndUnsafeInputs(t *testing.T) {
	t.Parallel()

	const (
		pw              = "correct-horse-battery"
		s               = "werkzeugsalt1234"
		validPBKDF2Hex  = "34518efc6d3cec57f908582b21a09ca8748ef126ff62f89cf5ed7020b64baaad"
		validPBKDF2600k = "15fdf2bf04be2a1f1b221208d4776d6f83c39eb117ce3bdf09a31451460bffe8"
		validScryptHex  = "1ccd5d13f26d814be32707449716dbcf407ead7900743d803abae4716a21de9c1dc2c11f3c20255ef45756de71e863cf01cd9a5a5c1adb8b3567ca49ab80f897"
		short15ByteHex  = "34518efc6d3cec57f908582b21a09c"
	)

	bad := []struct {
		name    string
		encoded string
	}{
		{"empty_encoded", ""},
		{"one_part", "scrypt:32768:8:1"},
		{"two_parts", "scrypt:32768:8:1$" + s},
		{"empty_digest_scrypt", "scrypt:32768:8:1$salt$"},
		{"empty_digest_pbkdf2", "pbkdf2:sha256:1000$" + s + "$"},
		{"short_digest_1_byte", "pbkdf2:sha256:1000$" + s + "$34"},
		{"short_digest_15_bytes", "pbkdf2:sha256:1000$" + s + "$" + short15ByteHex},
		{"odd_length_hex", "pbkdf2:sha256:1000$" + s + "$" + short15ByteHex + "a"},
		{"non_hex_digest", "pbkdf2:sha256:1000$" + s + "$zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz"},
		{"extra_dollar_in_digest", "pbkdf2:sha256:1000$" + s + "$" + validPBKDF2Hex + "$extra"},
		{"empty_salt_scrypt", "scrypt:32768:8:1$$" + validScryptHex},
		{"empty_salt_pbkdf2", "pbkdf2:sha256:1000$$" + validPBKDF2Hex},
		{"unknown_method", "argon2id$" + s + "$" + validPBKDF2Hex},
		{"empty_method", "$" + s + "$" + validPBKDF2Hex},

		// Malformed scrypt field counts
		{"scrypt_2_fields_bad", "scrypt:bad$" + s + "$" + validScryptHex},
		{"scrypt_2_fields_numeric", "scrypt:32768$" + s + "$" + validScryptHex},
		{"scrypt_3_fields", "scrypt:32768:8$" + s + "$" + validScryptHex},
		{"scrypt_5_fields", "scrypt:32768:8:1:extra$" + s + "$" + validScryptHex},

		// Non-numeric scrypt parameters
		{"scrypt_non_numeric_n", "scrypt:bad:8:1$" + s + "$" + validScryptHex},
		{"scrypt_non_numeric_r", "scrypt:32768:bad:1$" + s + "$" + validScryptHex},
		{"scrypt_non_numeric_p", "scrypt:32768:8:bad$" + s + "$" + validScryptHex},
		{"scrypt_empty_p", "scrypt:32768:8:$" + s + "$" + validScryptHex},

		// Invalid / non-power-of-two / oversized scrypt parameters
		{"scrypt_n_zero", "scrypt:0:8:1$" + s + "$" + validScryptHex},
		{"scrypt_n_one", "scrypt:1:8:1$" + s + "$" + validScryptHex},
		{"scrypt_n_negative", "scrypt:-16:8:1$" + s + "$" + validScryptHex},
		{"scrypt_n_not_power_of_two_3", "scrypt:3:8:1$" + s + "$" + validScryptHex},
		{"scrypt_n_not_power_of_two_48", "scrypt:48:8:1$" + s + "$" + validScryptHex},
		{"scrypt_n_above_max_262144", "scrypt:262144:1:1$" + s + "$" + validScryptHex},
		{"scrypt_r_zero", "scrypt:32768:0:1$" + s + "$" + validScryptHex},
		{"scrypt_r_negative", "scrypt:32768:-1:1$" + s + "$" + validScryptHex},
		{"scrypt_r_above_max_33", "scrypt:1024:33:1$" + s + "$" + validScryptHex},
		{"scrypt_p_zero", "scrypt:32768:8:0$" + s + "$" + validScryptHex},
		{"scrypt_p_negative", "scrypt:32768:8:-1$" + s + "$" + validScryptHex},
		{"scrypt_p_above_max_17", "scrypt:1024:4:17$" + s + "$" + validScryptHex},
		{"scrypt_nr_product_exceeds_limit_131072x16", "scrypt:131072:16:1$" + s + "$" + validScryptHex},
		{"scrypt_nr_product_exceeds_limit_65536x32", "scrypt:65536:32:1$" + s + "$" + validScryptHex},

		// Malformed / out-of-range pbkdf2 parameters
		{"pbkdf2_4_fields_extra", "pbkdf2:sha256:600000:extra$" + s + "$" + validPBKDF2600k},
		{"pbkdf2_empty_hash_name", "pbkdf2:$" + s + "$" + validPBKDF2Hex},
		{"pbkdf2_unsupported_md5", "pbkdf2:md5:1000$" + s + "$" + validPBKDF2Hex},
		{"pbkdf2_non_numeric_iterations", "pbkdf2:sha256:bad$" + s + "$" + validPBKDF2Hex},
		{"pbkdf2_empty_iterations", "pbkdf2:sha256:$" + s + "$" + validPBKDF2Hex},
		{"pbkdf2_zero_iterations", "pbkdf2:sha256:0$" + s + "$" + validPBKDF2Hex},
		{"pbkdf2_negative_iterations", "pbkdf2:sha256:-100$" + s + "$" + validPBKDF2Hex},
		{"pbkdf2_oversized_iterations", "pbkdf2:sha256:10000001$" + s + "$" + validPBKDF2Hex},
	}

	for _, tc := range bad {
		t.Run(tc.name, func(t *testing.T) {
			if Verify(tc.encoded, pw) {
				t.Fatalf("Verify(%q, pw) = true, want false", tc.encoded)
			}
			if Verify(tc.encoded, "") {
				t.Fatalf("Verify(%q, \"\") = true, want false", tc.encoded)
			}
		})
	}
}
