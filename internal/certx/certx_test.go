package certx

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestSelfSignedAndInspectLeaf(t *testing.T) {
	t.Parallel()

	chainPEM, keyPEM, err := SelfSigned("cert.example.org")
	if err != nil {
		t.Fatalf("SelfSigned failed: %v", err)
	}
	if _, err := tls.X509KeyPair(chainPEM, keyPEM); err != nil {
		t.Fatalf("X509KeyPair failed on SelfSigned output: %v", err)
	}

	leaf, err := InspectLeaf(chainPEM)
	if err != nil {
		t.Fatalf("InspectLeaf failed: %v", err)
	}
	if leaf.Subject.CommonName != "cert.example.org" {
		t.Fatalf("unexpected CommonName: %q", leaf.Subject.CommonName)
	}
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "cert.example.org" {
		t.Fatalf("unexpected DNSNames: %v", leaf.DNSNames)
	}

	// Leading comments, whitespace, and non-certificate blocks must be skipped.
	decorated := append([]byte("# comment header\n\n"), keyPEM...)
	decorated = append(decorated, []byte("\nbag attributes\n")...)
	decorated = append(decorated, chainPEM...)
	leaf2, err := InspectLeaf(decorated)
	if err != nil {
		t.Fatalf("InspectLeaf on decorated PEM failed: %v", err)
	}
	if !bytes.Equal(leaf.Raw, leaf2.Raw) {
		t.Fatalf("expected identical leaf DER")
	}

	// Missing CERTIFICATE block must return Chinese error.
	if _, err := InspectLeaf(keyPEM); err == nil || err.Error() != "未找到有效的 PEM 证书内容" {
		t.Fatalf("expected missing cert error, got %v", err)
	}
	if _, err := InspectLeaf([]byte("not a pem block")); err == nil || err.Error() != "未找到有效的 PEM 证书内容" {
		t.Fatalf("expected missing cert error on plain text, got %v", err)
	}

	// Malformed DER inside CERTIFICATE block must fail parsing.
	badCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("corrupt-der")})
	if _, err := InspectLeaf(badCert); err == nil {
		t.Fatalf("expected error on corrupt DER")
	}
}

func TestExtractMetadataKeyTypesSANsAndDERFingerprint(t *testing.T) {
	t.Parallel()

	notBefore := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	notAfter := time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)

	t.Run("EC256_and_DER_SHA256_invariance", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "E5", Organization: []string{"Let's Encrypt"}},
		}
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(0xdeadbeef),
			Subject:      pkix.Name{CommonName: "a.example.com"},
			DNSNames:     []string{"a.example.com", "b.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		plainPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		noisyPEM := []byte("# exported cert\r\n" + strings.ReplaceAll(string(plainPEM), "\n", "\r\n") + "\r\n# footer\r\n")

		leafPlain, err := InspectLeaf(plainPEM)
		if err != nil {
			t.Fatal(err)
		}
		leafNoisy, err := InspectLeaf(noisyPEM)
		if err != nil {
			t.Fatal(err)
		}

		metaPlain := ExtractMetadata(leafPlain, "")
		metaNoisy := ExtractMetadata(leafNoisy, "")

		wantSum := sha256.Sum256(der)
		wantHex := hex.EncodeToString(wantSum[:])
		if metaPlain.SHA256 != wantHex || metaNoisy.SHA256 != wantHex {
			t.Fatalf("DER SHA256 mismatch: plain=%s noisy=%s want=%s", metaPlain.SHA256, metaNoisy.SHA256, wantHex)
		}
		if len(metaPlain.SHA256) != 64 || metaPlain.SHA256 != strings.ToLower(metaPlain.SHA256) {
			t.Fatalf("expected 64-char lowercase hex SHA256, got %q", metaPlain.SHA256)
		}
		if metaPlain.KeyType != "EC256" {
			t.Fatalf("expected EC256, got %q", metaPlain.KeyType)
		}
		if metaPlain.Serial != "DEADBEEF" {
			t.Fatalf("expected uppercase hex serial DEADBEEF, got %q", metaPlain.Serial)
		}
		if metaPlain.Issuer != "Let's Encrypt E5" {
			t.Fatalf("expected friendly issuer 'Let's Encrypt E5', got %q", metaPlain.Issuer)
		}
		if metaPlain.IssuerDN != leafPlain.Issuer.String() {
			t.Fatalf("expected IssuerDN %q, got %q", leafPlain.Issuer.String(), metaPlain.IssuerDN)
		}
		if metaPlain.NotBefore != "2026-05-01T10:00:00Z" || metaPlain.NotAfter != "2026-08-01T10:00:00Z" {
			t.Fatalf("unexpected validity timestamps: %q -> %q", metaPlain.NotBefore, metaPlain.NotAfter)
		}
	})

	t.Run("RSA2048_and_empty_non_nil_SANs", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "Internal Root"},
		}
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(100),
			Subject:      pkix.Name{CommonName: "legacy.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, &priv.PublicKey, priv)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		meta := ExtractMetadata(leaf, "")
		if meta.KeyType != "RSA2048" {
			t.Fatalf("expected RSA2048, got %q", meta.KeyType)
		}
		if meta.SANs == nil || len(meta.SANs) != 0 {
			t.Fatalf("expected non-nil empty SANs slice, got %#v", meta.SANs)
		}
		rawJSON, err := json.Marshal(meta)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(rawJSON, []byte(`"sans":[]`)) {
			t.Fatalf("expected JSON sans:[], got %s", rawJSON)
		}
		if meta.Issuer != "Internal Root" {
			t.Fatalf("expected CN fallback issuer 'Internal Root', got %q", meta.Issuer)
		}
	})

	t.Run("ED25519_and_Org_only_issuer", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ca := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{Organization: []string{"Example Trust Services"}},
		}
		tpl := &x509.Certificate{
			SerialNumber: big.NewInt(7),
			Subject:      pkix.Name{CommonName: "ed.example.com"},
			DNSNames:     []string{"ed.example.com"},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, ca, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		meta := ExtractMetadata(leaf, "")
		if meta.KeyType != "ED25519" {
			t.Fatalf("expected ED25519, got %q", meta.KeyType)
		}
		if meta.Issuer != "Example Trust Services" {
			t.Fatalf("expected Org fallback issuer 'Example Trust Services', got %q", meta.Issuer)
		}
	})

	t.Run("Fallback_key_type_and_DN_fallback_issuer", func(t *testing.T) {
		synthetic := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Issuer:       pkix.Name{Country: []string{"CN"}},
			NotBefore:    notBefore,
			NotAfter:     notAfter,
		}
		if m := ExtractMetadata(synthetic, "EC384"); m.KeyType != "EC384" {
			t.Fatalf("expected fallback EC384, got %q", m.KeyType)
		}
		m2 := ExtractMetadata(synthetic, "")
		if m2.KeyType != "CUSTOM" {
			t.Fatalf("expected default fallback CUSTOM, got %q", m2.KeyType)
		}
		if m2.Issuer != synthetic.Issuer.String() {
			t.Fatalf("expected Issuer.String() fallback %q, got %q", synthetic.Issuer.String(), m2.Issuer)
		}
	})
}

func TestValidatePair(t *testing.T) {
	t.Parallel()

	now := time.Now()

	// Build an intermediate CA and a leaf certificate signed by it.
	caKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	caTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(10),
		Subject:               pkix.Name{CommonName: "Test Intermediate CA", Organization: []string{"Test CA"}},
		NotBefore:             now.Add(-2 * time.Hour),
		NotAfter:              now.Add(365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(20),
		Subject:      pkix.Name{CommonName: "app.example.com"},
		DNSNames:     []string{"app.example.com", "api.example.com"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(60 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})
	leafKeyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	leafKeyPEMNoNewline := bytes.TrimSpace(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: leafKeyDER}))

	t.Run("valid_leaf_plus_intermediate_chain_and_privkey_newline", func(t *testing.T) {
		fullInput := append(append([]byte{}, leafPEM...), caPEM...)
		keyInput := append([]byte("  \r\n"), leafKeyPEMNoNewline...)
		keyInputCopy := bytes.Clone(keyInput)

		leaf, files, meta, err := ValidatePair(fullInput, keyInput)
		if err != nil {
			t.Fatalf("ValidatePair failed: %v", err)
		}
		if !bytes.Equal(keyInput, keyInputCopy) {
			t.Fatalf("ValidatePair must not mutate caller privkeyPEM slice")
		}
		if leaf.Subject.CommonName != "app.example.com" {
			t.Fatalf("unexpected leaf CN: %q", leaf.Subject.CommonName)
		}
		if !bytes.Equal(files["cert.pem"], leafPEM) {
			t.Fatalf("cert.pem does not match leafPEM")
		}
		if !bytes.Equal(files["chain.pem"], caPEM) {
			t.Fatalf("chain.pem does not match intermediate caPEM")
		}
		wantFull := append(append([]byte{}, leafPEM...), caPEM...)
		if !bytes.Equal(files["fullchain.pem"], wantFull) {
			t.Fatalf("fullchain.pem mismatch")
		}
		if !bytes.HasSuffix(files["privkey.pem"], []byte("\n")) || bytes.HasSuffix(files["privkey.pem"], []byte("\n\n")) {
			t.Fatalf("privkey.pem must end with exactly one newline: %q", files["privkey.pem"])
		}
		if meta.KeyType != "EC256" || meta.Issuer != "Test CA Test Intermediate CA" {
			t.Fatalf("unexpected metadata: %+v", meta)
		}
	})

	t.Run("single_cert_fallback_chain", func(t *testing.T) {
		singleCert, singleKey, err := SelfSigned("solo.example.com")
		if err != nil {
			t.Fatal(err)
		}
		_, files, meta, err := ValidatePair(singleCert, bytes.TrimRight(singleKey, "\n"))
		if err != nil {
			t.Fatalf("ValidatePair on self-signed cert failed: %v", err)
		}
		if !bytes.Equal(files["cert.pem"], singleCert) {
			t.Fatalf("cert.pem mismatch")
		}
		if !bytes.Equal(files["chain.pem"], singleCert) {
			t.Fatalf("chain.pem should fall back to leaf certBytes when no intermediates present")
		}
		if !bytes.Equal(files["fullchain.pem"], singleCert) {
			t.Fatalf("fullchain.pem should contain single leaf cert without duplication")
		}
		if !bytes.HasSuffix(files["privkey.pem"], []byte("\n")) {
			t.Fatalf("privkey.pem missing trailing newline")
		}
		if meta.KeyType != "EC256" {
			t.Fatalf("expected EC256, got %q", meta.KeyType)
		}
	})

	t.Run("mismatched_key_rejected", func(t *testing.T) {
		_, otherKey, err := SelfSigned("other.example.com")
		if err != nil {
			t.Fatal(err)
		}
		_, _, _, err = ValidatePair(leafPEM, otherKey)
		if err == nil || err.Error() != "证书与私钥不匹配或 PEM 格式无效" {
			t.Fatalf("expected mismatch error, got %v", err)
		}
	})

	t.Run("expired_cert_rejected", func(t *testing.T) {
		expKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		expTpl := &x509.Certificate{
			SerialNumber: big.NewInt(99),
			Subject:      pkix.Name{CommonName: "expired.example.com"},
			DNSNames:     []string{"expired.example.com"},
			NotBefore:    now.Add(-48 * time.Hour),
			NotAfter:     now.Add(-time.Minute),
		}
		expDER, err := x509.CreateCertificate(rand.Reader, expTpl, expTpl, &expKey.PublicKey, expKey)
		if err != nil {
			t.Fatal(err)
		}
		expKeyDER, err := x509.MarshalECPrivateKey(expKey)
		if err != nil {
			t.Fatal(err)
		}
		expCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: expDER})
		expKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: expKeyDER})

		_, _, _, err = ValidatePair(expCertPEM, expKeyPEM)
		if err == nil || err.Error() != "证书已过期，请上传有效证书" {
			t.Fatalf("expected expired cert error '证书已过期，请上传有效证书', got %v", err)
		}
	})
}

func TestEffectiveStatus(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)

	// Empty or unparseable notAfter -> nil daysLeft and unchanged status.
	if st, d := EffectiveStatus("pending", "", now); st != "pending" || d != nil {
		t.Fatalf("expected ('pending', nil), got (%q, %v)", st, d)
	}
	if st, d := EffectiveStatus("valid", "not-rfc3339", now); st != "valid" || d != nil {
		t.Fatalf("expected ('valid', nil) on bad date, got (%q, %v)", st, d)
	}

	// Future valid certificate -> status preserved, non-negative daysLeft.
	future := now.Add(30*24*time.Hour + 6*time.Hour).Format(time.RFC3339)
	if st, d := EffectiveStatus("valid", future, now); st != "valid" || d == nil || *d != 30 {
		t.Fatalf("expected ('valid', 30), got (%q, %v)", st, d)
	}
	soon := now.Add(8 * time.Hour).Format(time.RFC3339)
	if st, d := EffectiveStatus("valid", soon, now); st != "valid" || d == nil || *d != 0 {
		t.Fatalf("expected ('valid', 0), got (%q, %v)", st, d)
	}

	// Exact boundary (now == exp) -> "expired" with -1.
	exact := now.Format(time.RFC3339)
	if st, d := EffectiveStatus("valid", exact, now); st != "expired" || d == nil || *d != -1 {
		t.Fatalf("expected ('expired', -1) at exact expiry, got (%q, %v)", st, d)
	}

	// Just-expired (<24h ago) valid -> "expired" with -1.
	justExp := now.Add(-3 * time.Hour).Format(time.RFC3339)
	if st, d := EffectiveStatus("valid", justExp, now); st != "expired" || d == nil || *d != -1 {
		t.Fatalf("expected ('expired', -1) for just-expired cert, got (%q, %v)", st, d)
	}

	// Multi-day expired valid -> "expired" with -N.
	multiExp := now.Add(-(5*24*time.Hour + 4*time.Hour)).Format(time.RFC3339)
	if st, d := EffectiveStatus("valid", multiExp, now); st != "expired" || d == nil || *d != -5 {
		t.Fatalf("expected ('expired', -5), got (%q, %v)", st, d)
	}

	// Non-"valid" statuses (e.g. "error", "renewing") must be preserved with negative daysLeft.
	if st, d := EffectiveStatus("error", multiExp, now); st != "error" || d == nil || *d != -5 {
		t.Fatalf("expected ('error', -5), got (%q, %v)", st, d)
	}
	if st, d := EffectiveStatus("renewing", justExp, now); st != "renewing" || d == nil || *d != -1 {
		t.Fatalf("expected ('renewing', -1), got (%q, %v)", st, d)
	}
}
