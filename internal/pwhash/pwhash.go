// Package pwhash implements Werkzeug-compatible password hashes so that
// passwords migrated from the previous Flask deployment keep working.
//
// Format: method$salt$hexdigest, e.g. "scrypt:32768:8:1$<salt>$<hex>".
package pwhash

import (
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/hex"
	"hash"
	"math/big"
	"strconv"
	"strings"

	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/scrypt"
)

const saltChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func salt(n int) (string, error) {
	if n <= 0 {
		return "", nil
	}
	var b strings.Builder
	b.Grow(n)
	max := big.NewInt(int64(len(saltChars)))
	for range n {
		v, err := rand.Int(rand.Reader, max)
		if err != nil {
			return "", err
		}
		b.WriteByte(saltChars[v.Int64()])
	}
	return b.String(), nil
}

// Hash returns a new scrypt hash in Werkzeug format.
func Hash(password string) (string, error) {
	s, err := salt(16)
	if err != nil {
		return "", err
	}
	key, err := scrypt.Key([]byte(password), []byte(s), 32768, 8, 1, 64)
	if err != nil {
		return "", err
	}
	return "scrypt:32768:8:1$" + s + "$" + hex.EncodeToString(key), nil
}

// Verify checks a password against a Werkzeug-format hash.
func Verify(encoded, password string) bool {
	parts := strings.SplitN(encoded, "$", 3)
	if len(parts) != 3 {
		return false
	}
	method, s, want := parts[0], parts[1], parts[2]
	if len(s) == 0 {
		return false
	}
	expected, err := hex.DecodeString(want)
	if err != nil || len(expected) < 16 {
		return false
	}
	fields := strings.Split(method, ":")
	var got []byte
	switch fields[0] {
	case "scrypt":
		n, r, p := 32768, 8, 1
		switch len(fields) {
		case 1:
		case 4:
			var err1, err2, err3 error
			n, err1 = strconv.Atoi(fields[1])
			r, err2 = strconv.Atoi(fields[2])
			p, err3 = strconv.Atoi(fields[3])
			if err1 != nil || err2 != nil || err3 != nil {
				return false
			}
		default:
			return false
		}
		if n <= 1 || n > 1<<17 || (n&(n-1)) != 0 || r < 1 || r > 32 || p < 1 || p > 16 || int64(n)*int64(r) > 1<<20 {
			return false
		}
		got, err = scrypt.Key([]byte(password), []byte(s), n, r, p, len(expected))
		if err != nil {
			return false
		}
	case "pbkdf2":
		if len(fields) < 1 || len(fields) > 3 {
			return false
		}
		name, iterations := "sha256", 600000
		if len(fields) >= 2 {
			name = fields[1]
		}
		if len(fields) == 3 {
			iterations, err = strconv.Atoi(fields[2])
			if err != nil {
				return false
			}
		}
		var h func() hash.Hash
		switch name {
		case "sha256":
			h = sha256.New
		case "sha512":
			h = sha512.New
		case "sha1":
			h = sha1.New
		default:
			return false
		}
		if iterations < 1 || iterations > 10_000_000 {
			return false
		}
		got = pbkdf2.Key([]byte(password), []byte(s), iterations, len(expected), h)
	default:
		return false
	}
	return subtle.ConstantTimeCompare(got, expected) == 1
}
