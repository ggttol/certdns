package issuer

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"os"
	"path/filepath"
	"sort"
	"time"

	"certdns/internal/certx"
	"certdns/internal/domain"
	"certdns/internal/store"
)

// TLSCertID returns the certificate ID currently exported for the management hostname.
func (m *Manager) TLSCertID(ctx context.Context) string {
	id, _ := m.Store.Setting(ctx, "tls_cert_id")
	return id
}

type tlsCandidate struct {
	cert     *store.Certificate
	notAfter time.Time
}

// pickTLS chooses the best valid certificate covering the management hostname:
// production over staging, then latest expiry, skipping unreadable or corrupt on-disk keypairs.
func (m *Manager) pickTLS(ctx context.Context) (*store.Certificate, error) {
	c, _, err := m.pickTLSFiles(ctx)
	return c, err
}

func (m *Manager) pickTLSFiles(ctx context.Context) (*store.Certificate, map[string][]byte, error) {
	certs, err := m.Store.Certificates(ctx)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	var candidates []tlsCandidate
	for _, c := range certs {
		if c.NotAfter == "" {
			continue
		}
		exp, err := time.Parse(time.RFC3339, c.NotAfter)
		if err != nil || !now.Before(exp) {
			continue
		}
		for _, san := range c.Domains {
			if domain.Covers(san, m.Hostname) {
				candidates = append(candidates, tlsCandidate{cert: c, notAfter: exp})
				break
			}
		}
	}
	if len(candidates) == 0 {
		return nil, nil, nil
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].cert.Staging != candidates[j].cert.Staging {
			return !candidates[i].cert.Staging
		}
		return candidates[i].notAfter.After(candidates[j].notAfter)
	})

	for _, cand := range candidates {
		files, err := m.ReadFiles(cand.cert.ID)
		if err != nil {
			continue
		}
		pair, err := tls.X509KeyPair(files["fullchain.pem"], files["privkey.pem"])
		if err != nil || len(pair.Certificate) == 0 {
			continue
		}
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil || !now.Before(leaf.NotAfter) {
			continue
		}
		return cand.cert, files, nil
	}
	return nil, nil, nil
}

// SyncTLS exports the chosen certificate to TLSDir (watched by nginx). When
// nothing covers the hostname, an existing valid keypair is preserved or a fresh
// self-signed placeholder is atomically written.
func (m *Manager) SyncTLS(ctx context.Context) error {
	if m.TLSDir == "" || m.Hostname == "" {
		return nil
	}
	m.tlsMu.Lock()
	defer m.tlsMu.Unlock()

	if err := os.MkdirAll(m.TLSDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(m.TLSDir, 0o700); err != nil {
		return err
	}

	fullchainPath := filepath.Join(m.TLSDir, "fullchain.pem")
	keyPath := filepath.Join(m.TLSDir, "privkey.pem")

	chosen, files, err := m.pickTLSFiles(ctx)
	if err != nil {
		return err
	}
	if chosen == nil {
		if err := m.Store.SetSettings(ctx, map[string]string{"tls_cert_id": ""}); err != nil {
			return err
		}
		if validExistingTLSPair(fullchainPath, keyPath, time.Now()) {
			return nil
		}
		chain, key, err := certx.SelfSigned(m.Hostname)
		if err != nil {
			return err
		}
		if err := writeTLSPair(m.TLSDir, chain, key); err != nil {
			return err
		}
		log.Printf("no valid certificate covers %s; wrote self-signed placeholder", m.Hostname)
		return nil
	}

	currentChain, err1 := os.ReadFile(fullchainPath)
	currentKey, err2 := os.ReadFile(keyPath)
	if err1 != nil || err2 != nil || !bytes.Equal(currentChain, files["fullchain.pem"]) || !bytes.Equal(currentKey, files["privkey.pem"]) {
		if err := writeTLSPair(m.TLSDir, files["fullchain.pem"], files["privkey.pem"]); err != nil {
			return err
		}
		log.Printf("exported certificate %s for %s", chosen.ID, m.Hostname)
	}
	return m.Store.SetSettings(ctx, map[string]string{"tls_cert_id": chosen.ID})
}

func validExistingTLSPair(fullchainPath, keyPath string, now time.Time) bool {
	chainPEM, err := os.ReadFile(fullchainPath)
	if err != nil {
		return false
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return false
	}
	pair, err := tls.X509KeyPair(chainPEM, keyPEM)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	return now.Before(leaf.NotAfter)
}

func writeTLSPair(dir string, fullchain, privkey []byte) error {
	keyTmp, err := writeSyncedTemp(dir, ".tmp-privkey-*", privkey)
	if err != nil {
		return err
	}
	chainTmp, err := writeSyncedTemp(dir, ".tmp-fullchain-*", fullchain)
	if err != nil {
		_ = os.Remove(keyTmp)
		return err
	}
	if err := os.Rename(keyTmp, filepath.Join(dir, "privkey.pem")); err != nil {
		_ = os.Remove(keyTmp)
		_ = os.Remove(chainTmp)
		return err
	}
	if err := os.Rename(chainTmp, filepath.Join(dir, "fullchain.pem")); err != nil {
		_ = os.Remove(chainTmp)
		return err
	}
	return syncDir(dir)
}
