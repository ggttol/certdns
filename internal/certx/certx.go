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
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"time"
)

// Metadata holds normalized X.509 leaf certificate attributes and DER fingerprint.
type Metadata struct {
	Subject   string   `json:"subject"`
	SANs      []string `json:"sans"`
	Serial    string   `json:"serial"`
	SHA256    string   `json:"sha256"`
	KeyType   string   `json:"key_type"`
	Signature string   `json:"signature"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Issuer    string   `json:"issuer"`
	IssuerDN  string   `json:"issuer_dn"`
}

// InspectLeaf decodes PEM blocks until the first CERTIFICATE block and parses it.
func InspectLeaf(certPEM []byte) (*x509.Certificate, error) {
	rest := certPEM
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, errors.New("未找到有效的 PEM 证书内容")
		}
		if block.Type == "CERTIFICATE" {
			return x509.ParseCertificate(block.Bytes)
		}
	}
}

// ExtractMetadata extracts display and storage metadata from a parsed leaf certificate.
func ExtractMetadata(leaf *x509.Certificate, fallbackKeyType string) Metadata {
	if leaf == nil {
		return Metadata{
			SANs:    []string{},
			KeyType: detectKeyType(nil, fallbackKeyType),
		}
	}
	sans := make([]string, len(leaf.DNSNames))
	copy(sans, leaf.DNSNames)

	var serial string
	if leaf.SerialNumber != nil {
		serial = strings.ToUpper(leaf.SerialNumber.Text(16))
	}

	sum := sha256.Sum256(leaf.Raw)
	subject := leaf.Subject.CommonName
	if subject == "" {
		subject = leaf.Subject.String()
	}

	return Metadata{
		Subject:   subject,
		SANs:      sans,
		Serial:    serial,
		SHA256:    hex.EncodeToString(sum[:]),
		KeyType:   detectKeyType(leaf.PublicKey, fallbackKeyType),
		Signature: leaf.SignatureAlgorithm.String(),
		NotBefore: leaf.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  leaf.NotAfter.UTC().Format(time.RFC3339),
		Issuer:    issuerFriendlyName(leaf),
		IssuerDN:  leaf.Issuer.String(),
	}
}

func detectKeyType(pub any, fallbackKeyType string) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		if k != nil && k.Curve != nil && k.Curve.Params() != nil {
			return fmt.Sprintf("EC%d", k.Curve.Params().BitSize)
		}
	case *rsa.PublicKey:
		if k != nil && k.N != nil {
			return fmt.Sprintf("RSA%d", k.N.BitLen())
		}
	case ed25519.PublicKey:
		return "ED25519"
	}
	if fallbackKeyType != "" {
		return fallbackKeyType
	}
	return "CUSTOM"
}

func issuerFriendlyName(c *x509.Certificate) string {
	if c.Issuer.CommonName != "" {
		if len(c.Issuer.Organization) > 0 && c.Issuer.Organization[0] != "" {
			return c.Issuer.Organization[0] + " " + c.Issuer.CommonName
		}
		return c.Issuer.CommonName
	}
	if len(c.Issuer.Organization) > 0 && c.Issuer.Organization[0] != "" {
		return c.Issuer.Organization[0]
	}
	return c.Issuer.String()
}

// ValidatePair verifies a fullchain + private key PEM pair, rejects expired leaf
// certificates, and splits normalized PEM files into cert.pem, chain.pem, fullchain.pem, privkey.pem.
func ValidatePair(fullchainPEM, privkeyPEM []byte) (*x509.Certificate, map[string][]byte, Metadata, error) {
	pair, err := tls.X509KeyPair(fullchainPEM, privkeyPEM)
	if err != nil {
		return nil, nil, Metadata{}, errors.New("证书与私钥不匹配或 PEM 格式无效")
	}
	if len(pair.Certificate) == 0 {
		return nil, nil, Metadata{}, errors.New("未包含有效证书")
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, nil, Metadata{}, errors.New("无法解析证书内容")
	}
	if !time.Now().Before(leaf.NotAfter) {
		return nil, nil, Metadata{}, errors.New("证书已过期，请上传有效证书")
	}

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]})
	var chainBuf bytes.Buffer
	for _, der := range pair.Certificate[1:] {
		_ = pem.Encode(&chainBuf, &pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	interBytes := chainBuf.Bytes()
	chainBytes := interBytes
	if len(chainBytes) == 0 {
		chainBytes = bytes.Clone(certBytes)
	}
	fullBytes := make([]byte, len(certBytes)+len(interBytes))
	copy(fullBytes, certBytes)
	copy(fullBytes[len(certBytes):], interBytes)

	trimmedKey := bytes.TrimSpace(privkeyPEM)
	normKey := make([]byte, len(trimmedKey)+1)
	copy(normKey, trimmedKey)
	normKey[len(trimmedKey)] = '\n'

	files := map[string][]byte{
		"cert.pem":      certBytes,
		"chain.pem":     chainBytes,
		"fullchain.pem": fullBytes,
		"privkey.pem":   normKey,
	}
	return leaf, files, ExtractMetadata(leaf, "CUSTOM"), nil
}

// SelfSigned generates a temporary ECDSA P-256 self-signed certificate valid for 30 days.
func SelfSigned(host string) (fullchainPEM, privkeyPEM []byte, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return nil, nil, err
	}
	if serial.Sign() <= 0 {
		serial = big.NewInt(1)
	}
	now := time.Now()
	var dnsNames []string
	if host != "" {
		dnsNames = []string{host}
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(30 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), nil
}

// EffectiveStatus computes the runtime certificate status and remaining days relative to now.
func EffectiveStatus(dbStatus, notAfter string, now time.Time) (status string, daysLeft *int) {
	if notAfter == "" {
		return dbStatus, nil
	}
	exp, err := time.Parse(time.RFC3339, notAfter)
	if err != nil {
		return dbStatus, nil
	}
	if !now.Before(exp) {
		d := -int(now.Sub(exp) / (24 * time.Hour))
		if d == 0 {
			d = -1
		}
		if dbStatus == "valid" {
			return "expired", &d
		}
		return dbStatus, &d
	}
	d := int(exp.Sub(now).Hours() / 24)
	return dbStatus, &d
}
