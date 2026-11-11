package secretbox

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Prefix identifies values encrypted with AES-256-GCM by this package.
const Prefix = "enc:v1:"

const keySize = 32

// Cipher wraps AES-256-GCM authenticated encryption for at-rest credentials.
type Cipher struct {
	aead cipher.AEAD
}

// NewFromKey constructs an AES-256-GCM Cipher from a 32-byte raw key.
func NewFromKey(raw []byte) (*Cipher, error) {
	if len(raw) != keySize {
		return nil, fmt.Errorf("secretbox: invalid key length %d, want %d", len(raw), keySize)
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, fmt.Errorf("secretbox: init aes: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secretbox: init gcm: %w", err)
	}
	return &Cipher{aead: aead}, nil
}

// LoadOrCreateKey loads a 32-byte key from CERTDNS_SECRET_KEY (64-char hex or
// base64-encoded 32 bytes) if set, or otherwise reads/atomically creates a
// 0600 hex key file at path inside a 0700 parent directory.
func LoadOrCreateKey(path string) (*Cipher, error) {
	if v := strings.TrimSpace(os.Getenv("CERTDNS_SECRET_KEY")); v != "" {
		return parseEnvKey(v)
	}
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("secretbox: key file path is empty")
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secretbox: create key dir: %w", err)
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, fmt.Errorf("secretbox: chmod key dir: %w", err)
	}

	c, err := readKeyFile(path)
	if err == nil {
		return c, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	var raw [keySize]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return nil, fmt.Errorf("secretbox: generate key: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".secret.key.tmp-*")
	if err != nil {
		return nil, fmt.Errorf("secretbox: create temp key file: %w", err)
	}
	tmpName := tmp.Name()
	removeTmp := true
	defer func() {
		if removeTmp {
			_ = os.Remove(tmpName)
		}
	}()

	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secretbox: chmod temp key file: %w", err)
	}

	var hexLine [keySize*2 + 1]byte
	hex.Encode(hexLine[:keySize*2], raw[:])
	hexLine[keySize*2] = '\n'
	if _, err := tmp.Write(hexLine[:]); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secretbox: write temp key file: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return nil, fmt.Errorf("secretbox: sync temp key file: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return nil, fmt.Errorf("secretbox: close temp key file: %w", err)
	}

	linkErr := os.Link(tmpName, path)
	_ = os.Remove(tmpName)
	removeTmp = false
	if linkErr != nil {
		if errors.Is(linkErr, os.ErrExist) {
			return readKeyFile(path)
		}
		return nil, fmt.Errorf("secretbox: link key file: %w", linkErr)
	}

	dirFile, err := os.Open(dir)
	if err != nil {
		return nil, fmt.Errorf("secretbox: open key dir: %w", err)
	}
	syncErr := dirFile.Sync()
	closeErr := dirFile.Close()
	if syncErr != nil && !errors.Is(syncErr, syscall.EINVAL) {
		return nil, fmt.Errorf("secretbox: sync key dir: %w", syncErr)
	}
	if closeErr != nil {
		return nil, fmt.Errorf("secretbox: close key dir: %w", closeErr)
	}

	return NewFromKey(raw[:])
}

func parseEnvKey(v string) (*Cipher, error) {
	if strings.ContainsAny(v, " \t\r\n") {
		return nil, errors.New("secretbox: invalid CERTDNS_SECRET_KEY: contains whitespace")
	}
	if len(v) == keySize*2 {
		if raw, err := hex.DecodeString(v); err == nil && len(raw) == keySize {
			return NewFromKey(raw)
		}
	} else {
		for _, enc := range [4]*base64.Encoding{
			base64.StdEncoding,
			base64.RawStdEncoding,
			base64.URLEncoding,
			base64.RawURLEncoding,
		} {
			if raw, err := enc.DecodeString(v); err == nil && len(raw) == keySize {
				return NewFromKey(raw)
			}
		}
	}
	return nil, errors.New("secretbox: invalid CERTDNS_SECRET_KEY: must be 64-char hex or base64-encoded 32-byte key")
}

func readKeyFile(path string) (*Cipher, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return nil, fmt.Errorf("secretbox: chmod key file: %w", err)
	}
	s := strings.TrimSpace(string(data))
	if len(s) != keySize*2 {
		return nil, fmt.Errorf("secretbox: invalid key file %s: expected 64 hex chars", path)
	}
	raw, err := hex.DecodeString(s)
	if err != nil || len(raw) != keySize {
		return nil, fmt.Errorf("secretbox: decode key file %s: %w", path, err)
	}
	return NewFromKey(raw)
}

// Seal encrypts plain with AES-256-GCM using aad as additional authenticated data.
// Empty plain returns "", nil. A nil Cipher returns plain unchanged.
// Values already starting with Prefix are still encrypted (never passed through).
func (c *Cipher) Seal(plain, aad string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if c == nil {
		return plain, nil
	}
	if c.aead == nil {
		return "", errors.New("secretbox: uninitialized cipher")
	}

	nonceSize := c.aead.NonceSize()
	buf := make([]byte, nonceSize, nonceSize+len(plain)+c.aead.Overhead())
	if _, err := io.ReadFull(rand.Reader, buf); err != nil {
		return "", fmt.Errorf("secretbox: generate nonce: %w", err)
	}

	var aadBytes []byte
	if aad != "" {
		aadBytes = []byte(aad)
	}
	sealed := c.aead.Seal(buf, buf, []byte(plain), aadBytes)

	out := make([]byte, len(Prefix)+base64.RawStdEncoding.EncodedLen(len(sealed)))
	copy(out, Prefix)
	base64.RawStdEncoding.Encode(out[len(Prefix):], sealed)
	return string(out), nil
}

// Open decrypts a Prefix-tagged value using aad.
// Empty stored returns "", nil. Unprefixed values are returned unchanged for
// legacy plaintext migration compatibility.
func (c *Cipher) Open(stored, aad string) (string, error) {
	if stored == "" {
		return "", nil
	}
	if !strings.HasPrefix(stored, Prefix) {
		return stored, nil
	}
	if c == nil || c.aead == nil {
		return "", errors.New("secretbox: nil cipher cannot decrypt encrypted value")
	}

	buf, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, Prefix))
	if err != nil {
		return "", fmt.Errorf("secretbox: decode ciphertext: %w", err)
	}
	nonceSize := c.aead.NonceSize()
	if len(buf) < nonceSize+c.aead.Overhead() {
		return "", errors.New("secretbox: ciphertext too short")
	}

	var aadBytes []byte
	if aad != "" {
		aadBytes = []byte(aad)
	}
	plain, err := c.aead.Open(nil, buf[:nonceSize], buf[nonceSize:], aadBytes)
	if err != nil {
		return "", fmt.Errorf("secretbox: open ciphertext: %w", err)
	}
	return string(plain), nil
}
