package issuer

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/go-acme/lego/v4/registration"

	"certdns/internal/alidns"
	"certdns/internal/certx"
	"certdns/internal/secretbox"
	"certdns/internal/store"
)

func newTestEnv(t *testing.T) (*store.Store, *Manager, string) {
	t.Helper()
	tmp := t.TempDir()
	rawKey := bytes.Repeat([]byte{0x42}, 32)
	cipher, err := secretbox.NewFromKey(rawKey)
	if err != nil {
		t.Fatalf("NewFromKey: %v", err)
	}
	st, err := store.Open(filepath.Join(tmp, "certdns.sqlite3"), cipher)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	dataDir := filepath.Join(tmp, "data")
	tlsDir := filepath.Join(tmp, "tls")
	mgr := New(st, dataDir, tlsDir, "cert.example.org")
	return st, mgr, tmp
}

func makeCertFiles(t *testing.T, notBefore, notAfter time.Time, dnsNames ...string) (map[string][]byte, *x509.Certificate) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		t.Fatalf("rand serial: %v", err)
	}
	cn := "example.com"
	if len(dnsNames) > 0 {
		cn = dnsNames[0]
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: cn},
		Issuer:       pkix.Name{Organization: []string{"Test CA"}, CommonName: "R3"},
		DNSNames:     dnsNames,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return map[string][]byte{
		"cert.pem":      certPEM,
		"chain.pem":     certPEM,
		"fullchain.pem": certPEM,
		"privkey.pem":   keyPEM,
	}, leaf
}

func TestWriteReadRemoveFilesAtomicAndValidation(t *testing.T) {
	_, mgr, _ := newTestEnv(t)
	now := time.Now()
	pairA, _ := makeCertFiles(t, now.Add(-time.Hour), now.Add(60*24*time.Hour), "a.example.org")
	pairB, _ := makeCertFiles(t, now.Add(-time.Hour), now.Add(90*24*time.Hour), "b.example.org")

	if err := mgr.WriteFiles("not-a-valid-hex-id", pairA); err == nil {
		t.Fatal("expected invalid id rejection in WriteFiles")
	}
	if _, err := mgr.ReadFiles("../escape"); err == nil {
		t.Fatal("expected invalid id rejection in ReadFiles")
	}
	if err := mgr.RemoveFiles("bad"); err == nil {
		t.Fatal("expected invalid id rejection in RemoveFiles")
	}

	certID := store.NewID()
	mismatched := map[string][]byte{
		"cert.pem":      pairA["cert.pem"],
		"chain.pem":     pairA["chain.pem"],
		"fullchain.pem": pairA["fullchain.pem"],
		"privkey.pem":   pairB["privkey.pem"],
	}
	if err := mgr.WriteFiles(certID, mismatched); err == nil {
		t.Fatal("expected mismatched keypair rejection")
	}
	if _, err := os.Stat(mgr.CertDir(certID)); !os.IsNotExist(err) {
		t.Fatalf("expected no cert dir created on failed keypair validation, got err=%v", err)
	}

	if err := mgr.WriteFiles(certID, pairA); err != nil {
		t.Fatalf("WriteFiles(pairA): %v", err)
	}
	dirInfo, err := os.Stat(mgr.CertDir(certID))
	if err != nil {
		t.Fatalf("Stat cert dir: %v", err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Fatalf("cert dir perm = %04o, want 0700", perm)
	}
	entries, err := os.ReadDir(mgr.CertDir(certID))
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}
	if len(entries) != 4 {
		t.Fatalf("expected exactly 4 files (no temp leftovers), got %d", len(entries))
	}
	for _, ent := range entries {
		if strings.HasPrefix(ent.Name(), ".tmp-") {
			t.Fatalf("unexpected leftover temp file: %s", ent.Name())
		}
		fi, err := ent.Info()
		if err != nil {
			t.Fatalf("Info(%s): %v", ent.Name(), err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Fatalf("%s perm = %04o, want 0600", ent.Name(), fi.Mode().Perm())
		}
	}

	// Atomic switch to pairB, then confirm failed overwrite preserves pairB intact.
	if err := mgr.WriteFiles(certID, pairB); err != nil {
		t.Fatalf("WriteFiles(pairB): %v", err)
	}
	if err := mgr.WriteFiles(certID, mismatched); err == nil {
		t.Fatal("expected mismatched overwrite rejection")
	}
	got, err := mgr.ReadFiles(certID)
	if err != nil {
		t.Fatalf("ReadFiles: %v", err)
	}
	for name, want := range pairB {
		if !bytes.Equal(got[name], want) {
			t.Fatalf("file %s modified after rejected overwrite", name)
		}
	}

	if err := mgr.RemoveFiles(certID); err != nil {
		t.Fatalf("RemoveFiles: %v", err)
	}
	if _, err := os.Stat(mgr.CertDir(certID)); !os.IsNotExist(err) {
		t.Fatalf("expected cert dir removed, stat err=%v", err)
	}
}

func TestBackfillCertMetadata(t *testing.T) {
	st, mgr, _ := newTestEnv(t)
	ctx := context.Background()
	now := time.Now()

	filesA, leafA := makeCertFiles(t, now.Add(-time.Hour), now.Add(30*24*time.Hour), "backfill.example.org")
	sumA := sha256.Sum256(leafA.Raw)
	wantSHA := hex.EncodeToString(sumA[:])

	idA := store.NewID()
	if err := mgr.WriteFiles(idA, filesA); err != nil {
		t.Fatalf("WriteFiles(idA): %v", err)
	}
	if err := st.InsertCertificate(ctx, &store.Certificate{
		ID:        idA,
		Domains:   []string{"backfill.example.org"},
		Status:    "valid",
		AutoRenew: true,
		NotBefore: leafA.NotBefore.UTC().Format(time.RFC3339),
		NotAfter:  leafA.NotAfter.UTC().Format(time.RFC3339),
		Issuer:    "Test CA R3",
		SHA256:    "",
	}); err != nil {
		t.Fatalf("InsertCertificate(idA): %v", err)
	}

	// Unissued queued certificate without cert.pem on disk should be skipped silently.
	idMissing := store.NewID()
	if err := st.InsertCertificate(ctx, &store.Certificate{
		ID:        idMissing,
		Domains:   []string{"pending.example.org"},
		Status:    "queued",
		AutoRenew: true,
	}); err != nil {
		t.Fatalf("InsertCertificate(idMissing): %v", err)
	}

	// Certificate with existing SHA256 should remain untouched.
	idExisting := store.NewID()
	existingSHA := strings.Repeat("a", 64)
	if err := st.InsertCertificate(ctx, &store.Certificate{
		ID:      idExisting,
		Domains: []string{"existing.example.org"},
		Status:  "valid",
		SHA256:  existingSHA,
	}); err != nil {
		t.Fatalf("InsertCertificate(idExisting): %v", err)
	}

	if err := mgr.BackfillCertMetadata(ctx); err != nil {
		t.Fatalf("BackfillCertMetadata: %v", err)
	}

	gotA, err := st.Certificate(ctx, idA)
	if err != nil {
		t.Fatalf("Certificate(idA): %v", err)
	}
	if gotA.SHA256 != wantSHA {
		t.Fatalf("idA SHA256 = %q, want %q", gotA.SHA256, wantSHA)
	}

	gotMissing, err := st.Certificate(ctx, idMissing)
	if err != nil {
		t.Fatalf("Certificate(idMissing): %v", err)
	}
	if gotMissing.SHA256 != "" {
		t.Fatalf("idMissing SHA256 = %q, want empty", gotMissing.SHA256)
	}

	gotExisting, err := st.Certificate(ctx, idExisting)
	if err != nil {
		t.Fatalf("Certificate(idExisting): %v", err)
	}
	if gotExisting.SHA256 != existingSHA {
		t.Fatalf("idExisting SHA256 = %q, want %q", gotExisting.SHA256, existingSHA)
	}
}

func TestAccountIsolationLegacyMigrationAndPKCS8(t *testing.T) {
	_, mgr, _ := newTestEnv(t)

	pathAlice := mgr.accountPath(ProductionURL, "alice@example.com")
	pathAliceUpper := mgr.accountPath(ProductionURL, "  ALICE@Example.com ")
	pathBob := mgr.accountPath(ProductionURL, "bob@example.com")
	if pathAlice != pathAliceUpper {
		t.Fatalf("expected case/space normalized accountPath to match: %s vs %s", pathAlice, pathAliceUpper)
	}
	if pathAlice == pathBob {
		t.Fatalf("expected distinct account paths for different emails, got %s", pathAlice)
	}

	// Multi-email isolation: saving Bob must not overwrite Alice.
	aliceAcct, err := mgr.loadAccount(ProductionURL, "alice@example.com")
	if err != nil {
		t.Fatalf("loadAccount(alice): %v", err)
	}
	aliceAcct.Registration = &registration.Resource{URI: "https://acme.test/acct/alice"}
	if err := mgr.saveAccount(ProductionURL, aliceAcct); err != nil {
		t.Fatalf("saveAccount(alice): %v", err)
	}

	bobAcct, err := mgr.loadAccount(ProductionURL, "bob@example.com")
	if err != nil {
		t.Fatalf("loadAccount(bob): %v", err)
	}
	bobAcct.Registration = &registration.Resource{URI: "https://acme.test/acct/bob"}
	if err := mgr.saveAccount(ProductionURL, bobAcct); err != nil {
		t.Fatalf("saveAccount(bob): %v", err)
	}

	reloadedAlice, err := mgr.loadAccount(ProductionURL, "alice@example.com")
	if err != nil {
		t.Fatalf("reload alice: %v", err)
	}
	reloadedBob, err := mgr.loadAccount(ProductionURL, "bob@example.com")
	if err != nil {
		t.Fatalf("reload bob: %v", err)
	}
	if reloadedAlice.GetRegistration().URI != "https://acme.test/acct/alice" {
		t.Fatalf("alice URI = %q", reloadedAlice.GetRegistration().URI)
	}
	if reloadedBob.GetRegistration().URI != "https://acme.test/acct/bob" {
		t.Fatalf("bob URI = %q", reloadedBob.GetRegistration().URI)
	}
	if reloadedAlice.KeyPEM == reloadedBob.KeyPEM {
		t.Fatal("expected distinct ACME keys for alice and bob")
	}

	// Legacy account-<sha256(dirURL)[:6]>.json auto-migration on matching email only.
	legacyKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	legacyDER, err := x509.MarshalECPrivateKey(legacyKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey: %v", err)
	}
	legacyObj := account{
		Email:        "legacy@example.com",
		KeyPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: legacyDER})),
		Registration: &registration.Resource{URI: "https://acme.test/acct/legacy"},
	}
	legacyRaw, _ := json.MarshalIndent(legacyObj, "", "  ")
	legacyPath := mgr.legacyAccountPath(StagingURL)
	if err := os.MkdirAll(filepath.Dir(legacyPath), 0o700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(legacyPath, legacyRaw, 0o600); err != nil {
		t.Fatalf("WriteFile legacy: %v", err)
	}

	// Different email must not adopt or remove legacy account.
	otherAcct, err := mgr.loadAccount(StagingURL, "other@example.com")
	if err != nil {
		t.Fatalf("loadAccount(other): %v", err)
	}
	if otherAcct.GetRegistration() != nil {
		t.Fatal("different email should not adopt legacy registration")
	}
	if _, err := os.Stat(legacyPath); err != nil {
		t.Fatalf("legacy file should remain for matching email: %v", err)
	}

	// Matching email (case-insensitive) migrates legacy file to new hashed path.
	migrated, err := mgr.loadAccount(StagingURL, "LEGACY@example.com")
	if err != nil {
		t.Fatalf("loadAccount(LEGACY): %v", err)
	}
	if migrated.GetRegistration() == nil || migrated.GetRegistration().URI != "https://acme.test/acct/legacy" {
		t.Fatalf("expected migrated registration, got %+v", migrated.GetRegistration())
	}
	newLegacyPath := mgr.accountPath(StagingURL, "legacy@example.com")
	if _, err := os.Stat(newLegacyPath); err != nil {
		t.Fatalf("expected migrated file at new path %s: %v", newLegacyPath, err)
	}

	// PKCS#8 key loading (RSA + ECDSA wrapped in PKCS#8 "PRIVATE KEY" PEM).
	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	pkcs8DER, err := x509.MarshalPKCS8PrivateKey(rsaPriv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	pkcs8Acct := &account{
		Email:        "pkcs8@example.com",
		KeyPEM:       string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8DER})),
		Registration: &registration.Resource{URI: "https://acme.test/acct/pkcs8"},
	}
	if err := mgr.saveAccount(ProductionURL, pkcs8Acct); err != nil {
		t.Fatalf("saveAccount(pkcs8): %v", err)
	}
	loadedPKCS8, err := mgr.loadAccount(ProductionURL, "pkcs8@example.com")
	if err != nil {
		t.Fatalf("loadAccount(pkcs8): %v", err)
	}
	signer, ok := loadedPKCS8.GetPrivateKey().(crypto.Signer)
	if !ok {
		t.Fatalf("expected crypto.Signer, got %T", loadedPKCS8.GetPrivateKey())
	}
	pubRSA, ok := signer.Public().(*rsa.PublicKey)
	if !ok || pubRSA.N.Cmp(rsaPriv.PublicKey.N) != 0 {
		t.Fatal("loaded PKCS#8 public key mismatch")
	}
}

type mockAliDNS struct {
	mu            sync.Mutex
	zonesByKey    map[string][]string
	records       map[string]alidns.Record
	nextID        int
	addCalls      int
	infoCalls     int
	deleteCalls   int
	listCalls     int
	forceInfoCode string
	onAdd         func(alidns.Record)
}

func newMockAliDNS(t *testing.T) (*mockAliDNS, *httptest.Server) {
	t.Helper()
	m := &mockAliDNS{
		zonesByKey: map[string][]string{},
		records:    map[string]alidns.Record{},
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.FormValue("Action")
		keyID := r.FormValue("AccessKeyId")

		m.mu.Lock()
		defer m.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		switch action {
		case "DescribeDomains":
			zones := m.zonesByKey[keyID]
			type domItem struct {
				DomainName string `json:"DomainName"`
			}
			items := make([]domItem, len(zones))
			for i, z := range zones {
				items[i] = domItem{DomainName: z}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"TotalCount": len(items),
				"Domains":    map[string]any{"Domain": items},
			})
		case "DescribeDomainRecords":
			m.listCalls++
			zone := r.FormValue("DomainName")
			var out []alidns.Record
			for _, rec := range m.records {
				if rec.DomainName == zone {
					out = append(out, rec)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"TotalCount":    len(out),
				"DomainRecords": map[string]any{"Record": out},
			})
		case "AddDomainRecord":
			m.addCalls++
			m.nextID++
			id := fmt.Sprintf("rec-%d", m.nextID)
			rec := alidns.Record{
				RecordID:   id,
				DomainName: r.FormValue("DomainName"),
				RR:         r.FormValue("RR"),
				Type:       r.FormValue("Type"),
				Value:      r.FormValue("Value"),
				TTL:        600,
				Status:     "ENABLE",
			}
			m.records[id] = rec
			cb := m.onAdd
			_ = json.NewEncoder(w).Encode(map[string]string{"RecordId": id})
			if cb != nil {
				go cb(rec)
			}
		case "DescribeDomainRecordInfo":
			m.infoCalls++
			if m.forceInfoCode != "" {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"Code":    m.forceInfoCode,
					"Message": "forced test error",
				})
				return
			}
			id := r.FormValue("RecordId")
			rec, ok := m.records[id]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"Code":    "DomainRecordNotBelongToUser",
					"Message": "record not found",
				})
				return
			}
			_ = json.NewEncoder(w).Encode(rec)
		case "DeleteDomainRecord":
			m.deleteCalls++
			id := r.FormValue("RecordId")
			if _, ok := m.records[id]; !ok {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{
					"Code":    "RecordId.NotFound",
					"Message": "not found",
				})
				return
			}
			delete(m.records, id)
			_ = json.NewEncoder(w).Encode(map[string]string{"RecordId": id})
		default:
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"Code": "UnsupportedAction"})
		}
	}))
	t.Cleanup(srv.Close)
	return m, srv
}

func TestProviderPresentCleanUpDeterminismAndAdoption(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	st, mgr, _ := newTestEnv(t)
	ctx := context.Background()

	ali, aliSrv := newMockAliDNS(t)
	ali.zonesByKey["LTAI_MAIN_KEY"] = []string{"example.com"}
	mgr.NewDNS = func(creds alidns.Credentials) *alidns.Client {
		c := alidns.New(creds)
		c.Endpoint = aliSrv.URL + "/"
		return c
	}

	acct, err := st.CreateDNSAccount(ctx, &store.DNSAccount{
		Name:            "主账号",
		Edition:         alidns.EditionCN,
		AccessKeyID:     "LTAI_MAIN_KEY",
		AccessKeySecret: "secret-main",
		IsDefault:       true,
		Enabled:         true,
		CachedZones:     []string{"example.com"},
	})
	if err != nil {
		t.Fatalf("CreateDNSAccount: %v", err)
	}
	if err := st.SaveDNSAccountCheck(ctx, acct.ID, []string{"example.com"}, ""); err != nil {
		t.Fatalf("SaveDNSAccountCheck: %v", err)
	}

	certID := store.NewID()
	p := &provider{
		ctx:       ctx,
		m:         mgr,
		certID:    certID,
		accountID: acct.ID,
		logf:      func(string, ...any) {},
		created:   map[string]store.Challenge{},
	}

	if timeout, interval := p.Timeout(); timeout != 10*time.Minute || interval != 3*time.Second {
		t.Fatalf("Timeout() = (%v, %v), want (10m, 3s)", timeout, interval)
	}

	// 1. Wildcard domain normalized to "example.com|tok-wild" in Present and matched in CleanUp.
	if err := p.Present("*.Example.COM", "tok-wild", "keyAuth-wild"); err != nil {
		t.Fatalf("Present wildcard: %v", err)
	}
	if _, ok := p.created["example.com|tok-wild"]; !ok {
		t.Fatalf("expected deterministic key 'example.com|tok-wild' in p.created, got %+v", p.created)
	}
	pending, err := st.Challenges(ctx)
	if err != nil || len(pending) != 1 {
		t.Fatalf("Challenges after Present = %d (err=%v), want 1", len(pending), err)
	}
	listBeforeClean := ali.listCalls
	if err := p.CleanUp("example.com", "tok-wild", "keyAuth-wild"); err != nil {
		t.Fatalf("CleanUp wildcard: %v", err)
	}
	if ali.listCalls != listBeforeClean {
		t.Fatal("CleanUp should use single RecordInfo instead of AllRecords pagination")
	}
	pending, _ = st.Challenges(ctx)
	if len(pending) != 0 {
		t.Fatalf("expected 0 challenges after CleanUp, got %d", len(pending))
	}

	// 2. Existing matching TXT record is adopted in Present and deleted in CleanUp.
	info := dns01.GetChallengeInfo("api.example.com", "keyAuth-existing")
	ali.mu.Lock()
	ali.records["rec-stale-77"] = alidns.Record{
		RecordID:   "rec-stale-77",
		DomainName: "example.com",
		RR:         "_acme-challenge.api",
		Type:       "TXT",
		Value:      info.Value,
		TTL:        600,
	}
	addsBefore := ali.addCalls
	ali.mu.Unlock()

	if err := p.Present("api.example.com", "tok-existing", "keyAuth-existing"); err != nil {
		t.Fatalf("Present existing: %v", err)
	}
	ali.mu.Lock()
	addsAfter := ali.addCalls
	ali.mu.Unlock()
	if addsAfter != addsBefore {
		t.Fatal("Present should adopt matching TXT record without calling AddDomainRecord")
	}
	pending, _ = st.Challenges(ctx)
	if len(pending) != 1 || pending[0].RecordID != "rec-stale-77" {
		t.Fatalf("expected adopted challenge rec-stale-77 in DB, got %+v", pending)
	}
	if err := p.CleanUp("API.Example.com", "tok-existing", "keyAuth-existing"); err != nil {
		t.Fatalf("CleanUp adopted: %v", err)
	}
	ali.mu.Lock()
	_, stillInDNS := ali.records["rec-stale-77"]
	ali.mu.Unlock()
	if stillInDNS {
		t.Fatal("expected adopted TXT record to be deleted from AliDNS on CleanUp")
	}
	pending, _ = st.Challenges(ctx)
	if len(pending) != 0 {
		t.Fatalf("expected 0 challenges after adopted CleanUp, got %d", len(pending))
	}
}

func TestRemoveChallengeIdempotencyAndFallback(t *testing.T) {
	st, mgr, _ := newTestEnv(t)
	ctx := context.Background()

	ali, aliSrv := newMockAliDNS(t)
	ali.zonesByKey["LTAI_ACCT_A"] = []string{"example.com"}
	ali.zonesByKey["LTAI_ACCT_B"] = []string{"example.com"}
	mgr.NewDNS = func(creds alidns.Credentials) *alidns.Client {
		c := alidns.New(creds)
		c.Endpoint = aliSrv.URL + "/"
		return c
	}

	acctA, err := st.CreateDNSAccount(ctx, &store.DNSAccount{
		Name:            "AccountA",
		Edition:         alidns.EditionCN,
		AccessKeyID:     "LTAI_ACCT_A",
		AccessKeySecret: "secret-a",
		IsDefault:       true,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("CreateDNSAccount A: %v", err)
	}
	_ = st.SaveDNSAccountCheck(ctx, acctA.ID, []string{"example.com"}, "")

	acctB, err := st.CreateDNSAccount(ctx, &store.DNSAccount{
		Name:            "AccountB",
		Edition:         alidns.EditionCN,
		AccessKeyID:     "LTAI_ACCT_B",
		AccessKeySecret: "secret-b",
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("CreateDNSAccount B: %v", err)
	}
	_ = st.SaveDNSAccountCheck(ctx, acctB.ID, []string{"example.com"}, "")

	// 1. Record already absent on AliDNS -> IsRecordNotFound -> row removed without error.
	chGone := store.Challenge{
		RecordID:      "rec-already-gone",
		CertificateID: store.NewID(),
		AccountID:     acctA.ID,
		Zone:          "example.com",
		RR:            "_acme-challenge",
		Value:         "val-gone",
	}
	if err := st.AddChallenge(ctx, chGone); err != nil {
		t.Fatalf("AddChallenge: %v", err)
	}
	if err := mgr.removeChallenge(ctx, chGone); err != nil {
		t.Fatalf("removeChallenge(gone) error = %v, want nil", err)
	}
	if rem, _ := st.Challenges(ctx); len(rem) != 0 {
		t.Fatalf("expected challenge row removed on IsRecordNotFound, got %d", len(rem))
	}

	// 2. InvalidAccessKeyId.NotFound must NOT be treated as record deleted; row stays queued.
	chAuthFail := store.Challenge{
		RecordID:      "rec-auth-fail",
		CertificateID: store.NewID(),
		AccountID:     acctA.ID,
		Zone:          "example.com",
		RR:            "_acme-challenge",
		Value:         "val-auth",
	}
	_ = st.AddChallenge(ctx, chAuthFail)
	ali.mu.Lock()
	ali.forceInfoCode = "InvalidAccessKeyId.NotFound"
	ali.mu.Unlock()
	if err := mgr.removeChallenge(ctx, chAuthFail); err == nil {
		t.Fatal("expected error on InvalidAccessKeyId.NotFound")
	}
	ali.mu.Lock()
	ali.forceInfoCode = ""
	ali.mu.Unlock()
	if rem, _ := st.Challenges(ctx); len(rem) != 1 {
		t.Fatalf("expected challenge row preserved on credential error, got %d", len(rem))
	}
	_ = st.RemoveChallenge(ctx, chAuthFail.RecordID)

	// 3. AccountA deleted -> fallback via MatchDomainAccount to AccountB and delete record.
	ali.mu.Lock()
	ali.records["rec-fallback-1"] = alidns.Record{
		RecordID:   "rec-fallback-1",
		DomainName: "example.com",
		RR:         "_acme-challenge",
		Type:       "TXT",
		Value:      "val-fb",
	}
	ali.mu.Unlock()
	chFallback := store.Challenge{
		RecordID:      "rec-fallback-1",
		CertificateID: store.NewID(),
		AccountID:     acctA.ID,
		Zone:          "example.com",
		RR:            "_acme-challenge",
		Value:         "val-fb",
	}
	_ = st.AddChallenge(ctx, chFallback)
	if err := st.DeleteDNSAccount(ctx, acctA.ID); err != nil {
		t.Fatalf("DeleteDNSAccount A: %v", err)
	}
	if err := mgr.removeChallenge(ctx, chFallback); err != nil {
		t.Fatalf("removeChallenge fallback: %v", err)
	}
	ali.mu.Lock()
	_, exists := ali.records["rec-fallback-1"]
	ali.mu.Unlock()
	if exists {
		t.Fatal("expected record deleted via fallback AccountB")
	}
	if rem, _ := st.Challenges(ctx); len(rem) != 0 {
		t.Fatalf("expected 0 remaining challenges, got %d", len(rem))
	}

	// 4. Orphan challenge for a zone hosted by no configured account -> row deleted directly.
	chOrphan := store.Challenge{
		RecordID:      "rec-orphan-zone",
		CertificateID: store.NewID(),
		AccountID:     store.NewID(), // non-existent account ID
		Zone:          "unhosted-domain.org",
		RR:            "_acme-challenge",
		Value:         "val-orphan",
	}
	_ = st.AddChallenge(ctx, chOrphan)
	if err := mgr.removeChallenge(ctx, chOrphan); err != nil {
		t.Fatalf("removeChallenge orphan zone: %v", err)
	}
	if rem, _ := st.Challenges(ctx); len(rem) != 0 {
		t.Fatalf("expected orphan challenge row removed when no account hosts zone, got %d", len(rem))
	}
}

func TestRunWorkerGracefulShutdownRequeuesWithoutAlert(t *testing.T) {
	t.Setenv("LEGO_DISABLE_CNAME_SUPPORT", "true")
	st, mgr, tmp := newTestEnv(t)
	ctx := context.Background()

	var webhookCalls atomic.Int32
	whSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookCalls.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(whSrv.Close)
	mgr.Webhook.AllowPrivate = true
	if err := st.SetSettings(ctx, map[string]string{"webhook_url": whSrv.URL + "/hook"}); err != nil {
		t.Fatalf("SetSettings webhook_url: %v", err)
	}

	ali, aliSrv := newMockAliDNS(t)
	ali.zonesByKey["LTAI_WORKER"] = []string{"example.org"}
	presented := make(chan struct{})
	var once sync.Once
	ali.onAdd = func(rec alidns.Record) {
		once.Do(func() { close(presented) })
	}
	mgr.NewDNS = func(creds alidns.Credentials) *alidns.Client {
		c := alidns.New(creds)
		c.Endpoint = aliSrv.URL + "/"
		return c
	}

	var nonceSeq atomic.Int64
	var acmeSrv *httptest.Server
	acmeSrv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Replay-Nonce", fmt.Sprintf("nonce-%d", nonceSeq.Add(1)))
		w.Header().Set("Content-Type", "application/json")
		base := acmeSrv.URL
		switch r.URL.Path {
		case "/directory":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"newNonce":   base + "/new-nonce",
				"newAccount": base + "/new-acct",
				"newOrder":   base + "/new-order",
			})
		case "/new-nonce":
			w.WriteHeader(http.StatusOK)
		case "/new-acct":
			w.Header().Set("Location", base+"/acct/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "valid"})
		case "/new-order":
			w.Header().Set("Location", base+"/order/1")
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "pending",
				"identifiers":    []map[string]string{{"type": "dns", "value": "cert.example.org"}},
				"authorizations": []string{base + "/authz/1"},
				"finalize":       base + "/finalize/1",
			})
		case "/authz/1":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":     "pending",
				"identifier": map[string]string{"type": "dns", "value": "cert.example.org"},
				"challenges": []map[string]any{
					{
						"type":   "dns-01",
						"status": "pending",
						"url":    base + "/chall/1",
						"token":  "tokshutdown1234567890",
					},
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(acmeSrv.Close)

	caPath := filepath.Join(tmp, "mock-acme-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: acmeSrv.Certificate().Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("WriteFile CA: %v", err)
	}
	t.Setenv("LEGO_CA_CERTIFICATES", caPath)

	mgr.DirectoryURL = func(bool) string { return acmeSrv.URL + "/directory" }
	mgr.pollInterval = 20 * time.Millisecond

	acct, err := st.CreateDNSAccount(ctx, &store.DNSAccount{
		Name:            "WorkerAccount",
		Edition:         alidns.EditionCN,
		AccessKeyID:     "LTAI_WORKER",
		AccessKeySecret: "secret-worker",
		Email:           "ops@example.org",
		IsDefault:       true,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("CreateDNSAccount: %v", err)
	}
	_ = st.SaveDNSAccountCheck(ctx, acct.ID, []string{"example.org"}, "")

	certID := store.NewID()
	jobID, err := st.CreateCertificateWithJob(ctx, &store.Certificate{
		ID:        certID,
		Domains:   []string{"cert.example.org"},
		AutoRenew: true,
		AccountID: acct.ID,
		KeyType:   "EC256",
		Source:    "acme",
	})
	if err != nil {
		t.Fatalf("CreateCertificateWithJob: %v", err)
	}

	workerCtx, cancelWorker := context.WithCancel(context.Background())
	defer cancelWorker()

	done := make(chan struct{})
	go func() {
		defer close(done)
		mgr.RunWorker(workerCtx)
	}()

	select {
	case <-presented:
		cancelWorker()
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for worker to present DNS-01 challenge")
	}

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for RunWorker graceful exit after cancellation")
	}

	job, err := st.Job(ctx, jobID)
	if err != nil {
		t.Fatalf("Job: %v", err)
	}
	if job.Status != "queued" {
		t.Fatalf("job.Status = %q, want 'queued' after graceful shutdown requeue (output:\n%s)", job.Status, job.Output)
	}
	if !strings.Contains(job.Output, "服务重启，任务已重新入队等待续跑") {
		t.Fatalf("expected requeue note in job output, got:\n%s", job.Output)
	}

	cert, err := st.Certificate(ctx, certID)
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}
	if cert.Status == "error" || cert.LastError != "" {
		t.Fatalf("certificate should not be marked error on graceful shutdown: status=%q last_error=%q", cert.Status, cert.LastError)
	}

	if rem, _ := st.Challenges(ctx); len(rem) != 0 {
		t.Fatalf("expected 0 leftover challenges after shutdown cleanup, got %d", len(rem))
	}
	if got := webhookCalls.Load(); got != 0 {
		t.Fatalf("webhookCalls = %d, want 0 during graceful shutdown", got)
	}
}

func TestJobLogRedactionAndQueueDue(t *testing.T) {
	st, mgr, _ := newTestEnv(t)
	ctx := context.Background()

	dueID := store.NewID()
	if err := st.InsertCertificate(ctx, &store.Certificate{
		ID:        dueID,
		Domains:   []string{"due.example.org"},
		Status:    "valid",
		AutoRenew: true,
		Source:    "acme",
		NotAfter:  time.Now().Add(10 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("InsertCertificate due: %v", err)
	}
	uploadID := store.NewID()
	if err := st.InsertCertificate(ctx, &store.Certificate{
		ID:        uploadID,
		Domains:   []string{"uploaded.example.org"},
		Status:    "valid",
		AutoRenew: true,
		Source:    "upload",
		NotAfter:  time.Now().Add(5 * 24 * time.Hour).UTC().Format(time.RFC3339),
	}); err != nil {
		t.Fatalf("InsertCertificate upload: %v", err)
	}

	n, err := mgr.QueueDue(ctx)
	if err != nil {
		t.Fatalf("QueueDue: %v", err)
	}
	if n != 1 {
		t.Fatalf("QueueDue queued = %d, want 1", n)
	}
	// Second scan is idempotent when job is already active.
	n2, err := mgr.QueueDue(ctx)
	if err != nil || n2 != 0 {
		t.Fatalf("second QueueDue = (%d, %v), want (0, nil)", n2, err)
	}

	jobs, err := st.Jobs(ctx, 10)
	if err != nil || len(jobs) != 1 {
		t.Fatalf("Jobs = %d (err=%v), want 1", len(jobs), err)
	}
	jl := &jobLog{m: mgr, id: jobs[0].ID}
	keyBlock := string(pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: []byte("super-secret-ec-private-key-material"),
	}))
	secretSample := "line1\n" + keyBlock + "line2\n"
	if _, err := jl.Write([]byte(secretSample)); err != nil {
		t.Fatalf("jobLog.Write: %v", err)
	}
	gotJob, err := st.Job(ctx, jobs[0].ID)
	if err != nil {
		t.Fatalf("Job: %v", err)
	}
	if strings.Contains(gotJob.Output, "PRIVATE KEY") {
		t.Fatalf("private key leaked into job output: %s", gotJob.Output)
	}
	if !strings.Contains(gotJob.Output, "[已隐藏私钥]") {
		t.Fatalf("expected redaction marker in job output: %s", gotJob.Output)
	}
}

func TestSyncTLSPlaceholderAndCorruptCandidateSkip(t *testing.T) {
	st, mgr, _ := newTestEnv(t)
	ctx := context.Background()
	now := time.Now()

	// 1. Initial SyncTLS with no matching certs creates valid self-signed placeholder.
	if err := mgr.SyncTLS(ctx); err != nil {
		t.Fatalf("initial SyncTLS: %v", err)
	}
	if gotID := mgr.TLSCertID(ctx); gotID != "" {
		t.Fatalf("TLSCertID = %q, want empty", gotID)
	}
	fullchainPath := filepath.Join(mgr.TLSDir, "fullchain.pem")
	privkeyPath := filepath.Join(mgr.TLSDir, "privkey.pem")
	if !validExistingTLSPair(fullchainPath, privkeyPath, time.Now()) {
		t.Fatal("expected valid self-signed TLS placeholder")
	}

	// 2. Expired placeholder on disk is regenerated automatically by SyncTLS.
	expiredFiles, _ := makeCertFiles(t, now.Add(-10*24*time.Hour), now.Add(-24*time.Hour), "cert.example.org")
	if err := os.WriteFile(fullchainPath, expiredFiles["fullchain.pem"], 0o600); err != nil {
		t.Fatalf("write expired fullchain: %v", err)
	}
	if err := os.WriteFile(privkeyPath, expiredFiles["privkey.pem"], 0o600); err != nil {
		t.Fatalf("write expired privkey: %v", err)
	}
	if err := mgr.SyncTLS(ctx); err != nil {
		t.Fatalf("SyncTLS over expired placeholder: %v", err)
	}
	if !validExistingTLSPair(fullchainPath, privkeyPath, time.Now()) {
		t.Fatal("expected expired placeholder to be regenerated with valid self-signed cert")
	}

	// 3. Mismatched placeholder keypair on disk is regenerated automatically.
	otherFiles, _ := makeCertFiles(t, now.Add(-time.Hour), now.Add(10*24*time.Hour), "cert.example.org")
	if err := os.WriteFile(privkeyPath, otherFiles["privkey.pem"], 0o600); err != nil {
		t.Fatalf("write mismatched privkey: %v", err)
	}
	if err := mgr.SyncTLS(ctx); err != nil {
		t.Fatalf("SyncTLS over mismatched placeholder: %v", err)
	}
	if !validExistingTLSPair(fullchainPath, privkeyPath, time.Now()) {
		t.Fatal("expected mismatched placeholder to be regenerated")
	}

	// 4. Two candidate certs cover cert.example.org; later-expiring one is corrupt on disk,
	// so SyncTLS skips it and exports the valid earlier-expiring candidate.
	corruptID := store.NewID()
	corruptFiles, corruptLeaf := makeCertFiles(t, now.Add(-time.Hour), now.Add(85*24*time.Hour), "*.example.org")
	if err := mgr.WriteFiles(corruptID, corruptFiles); err != nil {
		t.Fatalf("WriteFiles(corruptID): %v", err)
	}
	corruptMeta := certx.ExtractMetadata(corruptLeaf, "EC256")
	if err := st.InsertCertificate(ctx, &store.Certificate{
		ID:        corruptID,
		Domains:   []string{"*.example.org"},
		Status:    "valid",
		NotBefore: corruptMeta.NotBefore,
		NotAfter:  corruptMeta.NotAfter,
		Issuer:    corruptMeta.Issuer,
		SHA256:    corruptMeta.SHA256,
	}); err != nil {
		t.Fatalf("InsertCertificate(corruptID): %v", err)
	}
	// Corrupt privkey.pem on disk after write.
	if err := os.WriteFile(filepath.Join(mgr.CertDir(corruptID), "privkey.pem"), []byte("corrupt-key"), 0o600); err != nil {
		t.Fatalf("corrupt privkey: %v", err)
	}

	validID := store.NewID()
	validFiles, validLeaf := makeCertFiles(t, now.Add(-time.Hour), now.Add(45*24*time.Hour), "cert.example.org")
	if err := mgr.WriteFiles(validID, validFiles); err != nil {
		t.Fatalf("WriteFiles(validID): %v", err)
	}
	validMeta := certx.ExtractMetadata(validLeaf, "EC256")
	if err := st.InsertCertificate(ctx, &store.Certificate{
		ID:        validID,
		Domains:   []string{"cert.example.org"},
		Status:    "valid",
		NotBefore: validMeta.NotBefore,
		NotAfter:  validMeta.NotAfter,
		Issuer:    validMeta.Issuer,
		SHA256:    validMeta.SHA256,
	}); err != nil {
		t.Fatalf("InsertCertificate(validID): %v", err)
	}

	if err := mgr.SyncTLS(ctx); err != nil {
		t.Fatalf("SyncTLS with candidates: %v", err)
	}
	if gotID := mgr.TLSCertID(ctx); gotID != validID {
		t.Fatalf("TLSCertID = %q, want %q (skipping corrupt higher-expiry candidate)", gotID, validID)
	}
	exportedChain, err := os.ReadFile(fullchainPath)
	if err != nil {
		t.Fatalf("ReadFile exported fullchain: %v", err)
	}
	if !bytes.Equal(exportedChain, validFiles["fullchain.pem"]) {
		t.Fatal("exported fullchain.pem does not match valid candidate")
	}
	tlsEntries, err := os.ReadDir(mgr.TLSDir)
	if err != nil {
		t.Fatalf("ReadDir TLSDir: %v", err)
	}
	for _, ent := range tlsEntries {
		if strings.HasPrefix(ent.Name(), ".tmp-") {
			t.Fatalf("unexpected temp file in TLSDir: %s", ent.Name())
		}
	}
}
