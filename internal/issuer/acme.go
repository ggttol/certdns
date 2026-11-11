package issuer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/lego"
	legolog "github.com/go-acme/lego/v4/log"
	"github.com/go-acme/lego/v4/registration"

	"certdns/internal/alidns"
	"certdns/internal/certx"
	"certdns/internal/store"
)

const (
	ProductionURL = "https://acme-v02.api.letsencrypt.org/directory"
	StagingURL    = "https://acme-staging-v02.api.letsencrypt.org/directory"
)

func parseKeyType(s string) certcrypto.KeyType {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "EC384":
		return certcrypto.EC384
	case "RSA2048":
		return certcrypto.RSA2048
	case "RSA4096":
		return certcrypto.RSA4096
	default:
		return certcrypto.EC256
	}
}

type account struct {
	Email        string                 `json:"email"`
	KeyPEM       string                 `json:"key_pem"`
	Registration *registration.Resource `json:"registration"`
	key          crypto.PrivateKey
}

func (a *account) GetEmail() string                        { return a.Email }
func (a *account) GetRegistration() *registration.Resource { return a.Registration }
func (a *account) GetPrivateKey() crypto.PrivateKey        { return a.key }

func (m *Manager) accountPath(dirURL, email string) string {
	norm := strings.ToLower(strings.TrimSpace(email))
	sum := sha256.Sum256([]byte(dirURL + "\n" + norm))
	return filepath.Join(m.DataDir, "acme", fmt.Sprintf("account-%x.json", sum[:6]))
}

func (m *Manager) legacyAccountPath(dirURL string) string {
	sum := sha256.Sum256([]byte(dirURL))
	return filepath.Join(m.DataDir, "acme", fmt.Sprintf("account-%x.json", sum[:6]))
}

func parseAccountKey(keyPEM string) (crypto.Signer, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	if block == nil {
		return nil, errors.New("invalid account key PEM")
	}
	if ecKey, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return ecKey, nil
	}
	if pkcs8Key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if signer, ok := pkcs8Key.(crypto.Signer); ok {
			return signer, nil
		}
		return nil, errors.New("unsupported PKCS#8 private key type")
	}
	return nil, errors.New("unable to parse account private key")
}

func (m *Manager) loadAccount(dirURL, email string) (*account, error) {
	trimmedEmail := strings.TrimSpace(email)
	path := m.accountPath(dirURL, trimmedEmail)
	if raw, err := os.ReadFile(path); err == nil {
		var a account
		if json.Unmarshal(raw, &a) == nil && strings.EqualFold(strings.TrimSpace(a.Email), trimmedEmail) {
			if signer, err := parseAccountKey(a.KeyPEM); err == nil {
				a.key = signer
				return &a, nil
			}
		}
	} else if errors.Is(err, os.ErrNotExist) {
		legacyPath := m.legacyAccountPath(dirURL)
		if raw, lerr := os.ReadFile(legacyPath); lerr == nil {
			var a account
			if json.Unmarshal(raw, &a) == nil && strings.EqualFold(strings.TrimSpace(a.Email), trimmedEmail) {
				if signer, err := parseAccountKey(a.KeyPEM); err == nil {
					a.Email = trimmedEmail
					a.key = signer
					if err := m.saveAccount(dirURL, &a); err != nil {
						return nil, err
					}
					_ = os.Remove(legacyPath)
					return &a, nil
				}
			}
		}
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &account{
		Email:  trimmedEmail,
		key:    key,
		KeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
	}, nil
}

func (m *Manager) saveAccount(dirURL string, a *account) error {
	acmeDir := filepath.Join(m.DataDir, "acme")
	if err := os.MkdirAll(acmeDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(acmeDir, 0o700); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(a, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(m.accountPath(dirURL, a.Email), raw)
}

type provider struct {
	ctx       context.Context
	m         *Manager
	certID    string
	accountID string
	logf      func(string, ...any)
	mu        sync.Mutex
	created   map[string]store.Challenge
}

func challengeKey(domainName, token string) string {
	dom := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(domainName)), "*.")
	dom = strings.TrimSuffix(dom, ".")
	return dom + "|" + token
}

func (p *provider) Timeout() (time.Duration, time.Duration) {
	if p.m != nil && p.m.pollInterval > 0 {
		return 10 * time.Minute, p.m.pollInterval
	}
	return 10 * time.Minute, 3 * time.Second
}

func (p *provider) Present(domainName, token, keyAuth string) error {
	if err := p.ctx.Err(); err != nil {
		return err
	}
	info := dns01.GetChallengeInfo(domainName, keyAuth)
	fqdn := strings.TrimSuffix(info.EffectiveFQDN, ".")
	acct, dnsClient, zone, err := p.m.MatchDomainAccount(p.ctx, fqdn, p.accountID, false)
	if err != nil {
		return err
	}
	fqdnLower := strings.ToLower(fqdn)
	zoneLower := strings.ToLower(zone)
	rr := strings.TrimSuffix(fqdnLower, "."+zoneLower)
	if fqdnLower == zoneLower {
		rr = "@"
	}

	existing, err := dnsClient.AllRecords(p.ctx, alidns.RecordQuery{Zone: zone, RRKey: rr, TypeKey: "TXT"})
	if err != nil {
		return errors.New(alidns.Hint(err))
	}
	key := challengeKey(domainName, token)
	for _, r := range existing {
		if strings.EqualFold(r.RR, rr) && strings.EqualFold(r.Type, "TXT") && r.Value == info.Value {
			ch := store.Challenge{
				RecordID:      r.RecordID,
				CertificateID: p.certID,
				AccountID:     acct.ID,
				Zone:          zone,
				RR:            r.RR,
				Value:         info.Value,
			}
			if err := p.m.Store.AddChallenge(p.ctx, ch); err != nil {
				return err
			}
			p.mu.Lock()
			p.created[key] = ch
			p.mu.Unlock()
			p.logf("TXT 记录已存在并已接管 (%s): %s.%s (RecordId %s)", acct.Name, r.RR, zone, r.RecordID)
			return nil
		}
	}

	id, err := dnsClient.AddRecord(p.ctx, zone, alidns.RecordInput{RR: rr, Type: "TXT", Value: info.Value, TTL: 600})
	if err != nil {
		return errors.New(alidns.Hint(err))
	}
	ch := store.Challenge{
		RecordID:      id,
		CertificateID: p.certID,
		AccountID:     acct.ID,
		Zone:          zone,
		RR:            rr,
		Value:         info.Value,
	}
	if err := p.m.Store.AddChallenge(p.ctx, ch); err != nil {
		cleanCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		_ = dnsClient.DeleteRecord(cleanCtx, id)
		cancel()
		return err
	}
	p.mu.Lock()
	p.created[key] = ch
	p.mu.Unlock()
	p.logf("已通过 [%s] 添加 TXT 记录 %s.%s (RecordId %s)，等待权威 DNS 生效…", acct.Name, rr, zone, id)
	return nil
}

func (p *provider) CleanUp(domainName, token, keyAuth string) error {
	key := challengeKey(domainName, token)
	p.mu.Lock()
	ch, ok := p.created[key]
	delete(p.created, key)
	p.mu.Unlock()
	if !ok {
		return nil
	}
	cleanCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := p.m.removeChallenge(cleanCtx, ch); err != nil {
		p.logf("清理 TXT 记录失败，将在下次启动时重试: %s", alidns.Hint(err))
		return err
	}
	p.logf("已清理 TXT 记录 %s.%s", ch.RR, ch.Zone)
	return nil
}

// removeChallenge deletes a TXT challenge record idempotently once verified by RecordId and Value.
func (m *Manager) removeChallenge(ctx context.Context, ch store.Challenge) error {
	var dnsClient *alidns.Client
	if ch.AccountID != "" {
		_, client, err := m.AccountClient(ctx, ch.AccountID)
		if err == nil {
			dnsClient = client
		} else if !errors.Is(err, store.ErrNotFound) {
			return err
		}
	}
	if dnsClient == nil {
		_, client, _, err := m.MatchDomainAccount(ctx, ch.Zone, "", false)
		if err != nil {
			var znm zoneNotManagedError
			if errors.As(err, &znm) || errors.Is(err, store.ErrNotFound) {
				return m.Store.RemoveChallenge(ctx, ch.RecordID)
			}
			return err
		}
		dnsClient = client
	}

	rec, err := dnsClient.RecordInfo(ctx, ch.RecordID)
	if err != nil {
		if alidns.IsRecordNotFound(err) {
			return m.Store.RemoveChallenge(ctx, ch.RecordID)
		}
		return err
	}
	if rec.Value == ch.Value {
		if err := dnsClient.DeleteRecord(ctx, ch.RecordID); err != nil && !alidns.IsRecordNotFound(err) {
			return err
		}
	}
	return m.Store.RemoveChallenge(ctx, ch.RecordID)
}

type ctxRoundTripper struct {
	ctx  context.Context
	base http.RoundTripper
}

func (rt ctxRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := rt.ctx.Err(); err != nil {
		return nil, err
	}
	base := rt.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(req.WithContext(rt.ctx))
}

var legoLogMu sync.Mutex

func (m *Manager) process(ctx context.Context, job *store.Job) (*store.IssuedInfo, error) {
	jl := &jobLog{m: m, id: job.ID}
	logger := log.New(jl, "", 0)
	logf := func(format string, args ...any) { logger.Printf(format, args...) }

	cert, err := m.Store.Certificate(ctx, job.CertificateID)
	if err != nil {
		return nil, errors.New("证书记录不存在")
	}
	if cert.Source == "upload" {
		return nil, errors.New("手动上传的外部证书不支持 ACME 自动续期，请上传新证书文件")
	}

	var contactEmail string
	for _, d := range cert.Domains {
		acct, _, zone, err := m.MatchDomainAccount(ctx, d, cert.AccountID, true)
		if err != nil {
			return nil, err
		}
		if contactEmail == "" && acct.Email != "" {
			contactEmail = acct.Email
		}
		logf("域名 %s 匹配到阿里云账户 [%s] 托管主域名 %s", d, acct.Name, zone)
	}
	if contactEmail == "" {
		contactEmail, _ = m.Store.Setting(ctx, "acme_email")
	}

	dirURL := m.DirectoryURL(cert.Staging)
	env := "正式环境"
	if cert.Staging {
		env = "测试环境"
	}
	keyType := cert.KeyType
	if keyType == "" {
		keyType = "EC256"
	}
	actionLabel := map[string]string{"issue": "签发", "renew": "续期"}[job.Kind]
	if actionLabel == "" {
		actionLabel = "签发"
	}
	logf("开始%s: %s (%s, 密钥算法: %s)", actionLabel, strings.Join(cert.Domains, ", "), env, keyType)

	acct, err := m.loadAccount(dirURL, contactEmail)
	if err != nil {
		return nil, err
	}
	cfg := lego.NewConfig(acct)
	cfg.CADirURL = dirURL
	cfg.UserAgent = "certdns/2.0"
	cfg.Certificate.KeyType = parseKeyType(keyType)
	cfg.Certificate.Timeout = 2 * time.Minute
	origTransport := cfg.HTTPClient.Transport
	cfg.HTTPClient.Transport = ctxRoundTripper{ctx: ctx, base: origTransport}
	if tr, ok := origTransport.(*http.Transport); ok {
		defer tr.CloseIdleConnections()
	}

	legoLogMu.Lock()
	previous := legolog.Logger
	legolog.Logger = logger
	defer func() {
		legolog.Logger = previous
		legoLogMu.Unlock()
	}()

	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("无法连接 ACME 服务: %w", err)
	}
	p := &provider{
		ctx:       ctx,
		m:         m,
		certID:    cert.ID,
		accountID: cert.AccountID,
		logf:      logf,
		created:   map[string]store.Challenge{},
	}
	if err := client.Challenge.SetDNS01Provider(p,
		dns01.AddRecursiveNameservers(m.Resolvers),
		dns01.AddDNSTimeout(10*time.Second),
		dns01.WrapPreCheck(func(domain, fqdn, value string, check dns01.PreCheckFunc) (bool, error) {
			if err := ctx.Err(); err != nil {
				// lego's wait.For only terminates the polling loop early when stop == true.
				return true, err
			}
			return check(fqdn, value)
		}),
	); err != nil {
		return nil, err
	}

	if acct.Registration == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, fmt.Errorf("ACME 账户注册失败: %w", err)
		}
		acct.Registration = reg
		if err := m.saveAccount(dirURL, acct); err != nil {
			return nil, err
		}
		logf("已注册 ACME 账户")
	}

	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: cert.Domains, Bundle: true})
	if err != nil {
		return nil, fmt.Errorf("证书申请失败: %w", err)
	}
	leaf, err := certx.InspectLeaf(res.Certificate)
	if err != nil {
		return nil, err
	}

	certBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	chainBytes := res.IssuerCertificate
	if len(bytes.TrimSpace(chainBytes)) == 0 {
		chainBytes = certBytes
	}
	trimmedKey := bytes.TrimSpace(res.PrivateKey)
	privKey := make([]byte, len(trimmedKey)+1)
	copy(privKey, trimmedKey)
	privKey[len(trimmedKey)] = '\n'

	files := map[string][]byte{
		"cert.pem":      certBytes,
		"chain.pem":     chainBytes,
		"fullchain.pem": res.Certificate,
		"privkey.pem":   privKey,
	}
	if err := m.WriteFiles(cert.ID, files); err != nil {
		return nil, err
	}

	meta := certx.ExtractMetadata(leaf, keyType)
	info := &store.IssuedInfo{
		NotBefore: meta.NotBefore,
		NotAfter:  meta.NotAfter,
		Issuer:    meta.Issuer,
		SHA256:    meta.SHA256,
	}
	logf("证书已保存，有效期至 %s", leaf.NotAfter.Local().Format("2006-01-02 15:04"))
	return info, nil
}
