package issuer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"certdns/internal/certx"
	"certdns/internal/store"
)

var pemFiles = [4]string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"}

// CertDir returns the on-disk directory holding PEM files for certificate id.
func (m *Manager) CertDir(id string) string {
	return filepath.Join(m.DataDir, "certs", id)
}

// ReadFiles reads cert.pem, chain.pem, fullchain.pem, and privkey.pem for certificate id.
func (m *Manager) ReadFiles(id string) (map[string][]byte, error) {
	if !store.ValidID(id) {
		return nil, errors.New("invalid id")
	}
	dir := m.CertDir(id)
	out := make(map[string][]byte, len(pemFiles))
	for _, name := range pemFiles {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return nil, err
		}
		out[name] = b
	}
	return out, nil
}

// WriteFiles validates the certificate/key pair and atomically writes all four PEM files.
// All temporary files are written, chmodded 0600, synced, and closed before any rename occurs.
func (m *Manager) WriteFiles(id string, files map[string][]byte) error {
	if !store.ValidID(id) {
		return errors.New("invalid id")
	}
	if _, err := tls.X509KeyPair(files["fullchain.pem"], files["privkey.pem"]); err != nil {
		return fmt.Errorf("invalid certificate/private key pair: %w", err)
	}
	for _, name := range pemFiles {
		if len(files[name]) == 0 {
			return fmt.Errorf("missing %s content", name)
		}
	}

	dir := m.CertDir(id)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return err
	}

	var tmpPaths [len(pemFiles)]string
	cleanup := true
	defer func() {
		if cleanup {
			for _, p := range tmpPaths {
				if p != "" {
					_ = os.Remove(p)
				}
			}
		}
	}()

	for i, name := range pemFiles {
		p, err := writeSyncedTemp(dir, ".tmp-"+name+"-*", files[name])
		if err != nil {
			return err
		}
		tmpPaths[i] = p
	}
	for i, name := range pemFiles {
		if err := os.Rename(tmpPaths[i], filepath.Join(dir, name)); err != nil {
			return err
		}
		tmpPaths[i] = ""
	}
	cleanup = false
	return syncDir(dir)
}

// RemoveFiles deletes the on-disk PEM directory for certificate id.
func (m *Manager) RemoveFiles(id string) error {
	if !store.ValidID(id) {
		return errors.New("invalid id")
	}
	return os.RemoveAll(m.CertDir(id))
}

// BackfillCertMetadata populates missing SHA-256 leaf DER fingerprints in SQLite
// from existing cert.pem files on disk. Unissued certificates without cert.pem are skipped.
func (m *Manager) BackfillCertMetadata(ctx context.Context) error {
	certs, err := m.Store.Certificates(ctx)
	if err != nil {
		return err
	}
	var firstErr error
	for _, c := range certs {
		if c.SHA256 != "" || !store.ValidID(c.ID) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(m.CertDir(c.ID), "cert.pem"))
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		leaf, err := certx.InspectLeaf(raw)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("cert %s: %w", c.ID, err)
			}
			continue
		}
		meta := certx.ExtractMetadata(leaf, c.KeyType)
		if err := m.Store.UpdateCertificateSHA256(ctx, c.ID, meta.SHA256); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func writeSyncedTemp(dir, pattern string, data []byte) (string, error) {
	tmp, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return "", err
	}
	name := tmp.Name()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		_ = os.Remove(name)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return "", err
	}
	return name, nil
}

func syncDir(dir string) error {
	df, err := os.Open(dir)
	if err != nil {
		return err
	}
	syncErr := df.Sync()
	closeErr := df.Close()
	if syncErr != nil && !errors.Is(syncErr, syscall.EINVAL) {
		return syncErr
	}
	return closeErr
}

func atomicWrite(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmpName, err := writeSyncedTemp(dir, ".tmp-*", data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		_ = os.Remove(tmpName)
		return err
	}
	return syncDir(dir)
}
