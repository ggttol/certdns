package store

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"certdns/internal/secretbox"
)

func testCipher(t *testing.T, fill byte) *secretbox.Cipher {
	t.Helper()
	c, err := secretbox.NewFromKey(bytes.Repeat([]byte{fill}, 32))
	if err != nil {
		t.Fatalf("NewFromKey: %v", err)
	}
	return c
}

func TestValidID(t *testing.T) {
	t.Parallel()
	if !ValidID(NewID()) {
		t.Fatal("NewID should satisfy ValidID")
	}
	if !ValidID("0123456789abcdef0123456789abcdef") {
		t.Fatal("valid 32-char lowercase hex rejected")
	}
	for _, bad := range []string{
		"",
		"0123456789abcdef0123456789abcde",
		"0123456789abcdef0123456789abcdef0",
		"0123456789ABCDEF0123456789abcdef",
		"0123456789abcdef0123456789abcdeg",
		"../0123456789abcdef0123456789abc",
	} {
		if ValidID(bad) {
			t.Fatalf("expected ValidID(%q) = false", bad)
		}
	}
}

func TestLegacyMigrationEncryptionAndPermissions(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	dataDir := filepath.Join(t.TempDir(), "legacy-data")
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dataDir, 0o755); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(dataDir, "certdns.sqlite3")

	rawDB, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	legacyDDL := `
	CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
	CREATE TABLE users (
		id TEXT PRIMARY KEY,
		username TEXT NOT NULL UNIQUE,
		display_name TEXT NOT NULL DEFAULT '',
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'admin',
		enabled INTEGER NOT NULL DEFAULT 1,
		last_login_at TEXT,
		last_login_ip TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL);
	CREATE TABLE dns_accounts (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		edition TEXT NOT NULL DEFAULT 'cn',
		region_id TEXT NOT NULL DEFAULT 'cn-hangzhou',
		endpoint TEXT NOT NULL DEFAULT 'https://alidns.aliyuncs.com/',
		access_key_id TEXT NOT NULL,
		access_key_secret TEXT NOT NULL,
		email TEXT NOT NULL DEFAULT '',
		is_default INTEGER NOT NULL DEFAULT 0,
		enabled INTEGER NOT NULL DEFAULT 1,
		cached_zones TEXT NOT NULL DEFAULT '[]',
		last_checked_at TEXT,
		last_error TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL);
	CREATE TABLE certificates (
		id TEXT PRIMARY KEY,
		domains TEXT NOT NULL,
		staging INTEGER NOT NULL DEFAULT 0,
		status TEXT NOT NULL,
		auto_renew INTEGER NOT NULL DEFAULT 1,
		not_before TEXT,
		not_after TEXT,
		issuer TEXT,
		last_error TEXT,
		created_at TEXT NOT NULL,
		updated_at TEXT NOT NULL);
	CREATE TABLE challenges (
		record_id TEXT PRIMARY KEY,
		certificate_id TEXT NOT NULL,
		zone TEXT NOT NULL,
		rr TEXT NOT NULL,
		value TEXT NOT NULL,
		created_at TEXT NOT NULL);
	CREATE TABLE sessions (
		token_hash TEXT PRIMARY KEY,
		csrf TEXT NOT NULL,
		expires_at INTEGER NOT NULL);
	CREATE TABLE login_attempts (at INTEGER NOT NULL);
	`
	if _, err := rawDB.Exec(legacyDDL); err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}

	now := Now()
	adminID := NewID()
	acctID := NewID()
	certID := NewID()
	const (
		plainAcctSecret   = "LegacyPlaintextAliSecret_987654321"
		plainLegacySecret = "DuplicateSettingsAliSecret_1234567"
		plainWebhookToken = "WebhookPlainSecretToken_abcdef1234"
	)
	webhookURL := "https://oapi.dingtalk.com/robot/send?access_token=" + plainWebhookToken

	if _, err := rawDB.Exec(`INSERT INTO users(id,username,display_name,password_hash,role,enabled,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?)`, adminID, "admin", "管理员", "scrypt:32768:8:1$s$00112233445566778899aabbccddeeff", "admin", 1, now, now); err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}
	if _, err := rawDB.Exec(`INSERT INTO dns_accounts(id,name,edition,region_id,endpoint,access_key_id,access_key_secret,email,is_default,enabled,cached_zones,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		acctID, "主账号", "cn", "cn-hangzhou", "https://alidns.aliyuncs.com/", "LTAI5tLegacyKeyID", plainAcctSecret, "ops@example.com", 1, 1, `["example.org"]`, now, now); err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}
	if _, err := rawDB.Exec(`INSERT INTO certificates(id,domains,staging,status,auto_renew,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?)`, certID, `["cert.example.org"]`, 0, "valid", 1, now, now); err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}
	for k, v := range map[string]string{
		"password_hash": "scrypt:32768:8:1$s$00112233445566778899aabbccddeeff",
		"alidns_key_id": "LTAI5tLegacyKeyID",
		"alidns_secret": plainLegacySecret,
		"webhook_url":   webhookURL,
		"acme_email":    "ops@example.com",
	} {
		if _, err := rawDB.Exec(`INSERT INTO settings(key,value) VALUES(?,?)`, k, v); err != nil {
			_ = rawDB.Close()
			t.Fatal(err)
		}
	}
	if _, err := rawDB.Exec(`INSERT INTO sessions(token_hash,csrf,expires_at) VALUES(?,?,?)`,
		"orphanhash", "csrfval", time.Now().Add(time.Hour).Unix()); err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}
	if _, err := rawDB.Exec(`INSERT INTO login_attempts(at) VALUES(?)`, time.Now().Unix()); err != nil {
		_ = rawDB.Close()
		t.Fatal(err)
	}
	if err := rawDB.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0o644); err != nil {
		t.Fatal(err)
	}

	cipher1 := testCipher(t, 0x42)
	st, err := Open(dbPath, cipher1)
	if err != nil {
		t.Fatalf("Open legacy DB: %v", err)
	}

	dirInfo, err := os.Stat(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("expected dir perm 0700, got %04o", got)
	}
	fileInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if got := fileInfo.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected db perm 0600, got %04o", got)
	}

	for _, deletedKey := range []string{"password_hash", "alidns_key_id", "alidns_secret"} {
		v, err := st.Setting(ctx, deletedKey)
		if err != nil {
			t.Fatalf("Setting(%s): %v", deletedKey, err)
		}
		if v != "" {
			t.Fatalf("expected legacy setting %s deleted, got %q", deletedKey, v)
		}
	}
	if got, err := st.Setting(ctx, "acme_email"); err != nil || got != "ops@example.com" {
		t.Fatalf("expected acme_email preserved, got %q, err=%v", got, err)
	}
	if got, err := st.Setting(ctx, "webhook_url"); err != nil || got != webhookURL {
		t.Fatalf("expected decrypted webhook_url %q, got %q, err=%v", webhookURL, got, err)
	}

	acct, err := st.DNSAccount(ctx, acctID)
	if err != nil {
		t.Fatalf("DNSAccount: %v", err)
	}
	if acct.AccessKeySecret != plainAcctSecret {
		t.Fatalf("expected decrypted secret %q, got %q", plainAcctSecret, acct.AccessKeySecret)
	}

	cert, err := st.Certificate(ctx, certID)
	if err != nil {
		t.Fatalf("Certificate: %v", err)
	}
	if cert.SHA256 != "" || cert.KeyType != "EC256" || cert.Source != "acme" {
		t.Fatalf("unexpected migrated cert defaults: %+v", cert)
	}
	fp := strings.Repeat("b", 64)
	if err := st.UpdateCertificateSHA256(ctx, certID, fp); err != nil {
		t.Fatalf("UpdateCertificateSHA256: %v", err)
	}
	if cert, err = st.Certificate(ctx, certID); err != nil || cert.SHA256 != fp {
		t.Fatalf("expected SHA256 %q, got %+v (err=%v)", fp, cert, err)
	}

	if err := st.Close(); err != nil {
		t.Fatal(err)
	}

	// Verify raw SQLite storage is encrypted and orphan sessions / plaintext pages are scrubbed.
	checkDB, err := sql.Open("sqlite", "file:"+dbPath)
	if err != nil {
		t.Fatal(err)
	}
	var rawSecret, rawWebhook string
	if err := checkDB.QueryRow(`SELECT access_key_secret FROM dns_accounts WHERE id=?`, acctID).Scan(&rawSecret); err != nil {
		_ = checkDB.Close()
		t.Fatal(err)
	}
	if !strings.HasPrefix(rawSecret, secretbox.Prefix) {
		_ = checkDB.Close()
		t.Fatalf("expected raw dns_accounts secret to start with %q, got %q", secretbox.Prefix, rawSecret)
	}
	if err := checkDB.QueryRow(`SELECT value FROM settings WHERE key='webhook_url'`).Scan(&rawWebhook); err != nil {
		_ = checkDB.Close()
		t.Fatal(err)
	}
	if !strings.HasPrefix(rawWebhook, secretbox.Prefix) {
		_ = checkDB.Close()
		t.Fatalf("expected raw webhook_url to start with %q, got %q", secretbox.Prefix, rawWebhook)
	}
	var orphanCount int
	if err := checkDB.QueryRow(`SELECT COUNT(*) FROM sessions`).Scan(&orphanCount); err != nil {
		_ = checkDB.Close()
		t.Fatal(err)
	}
	if orphanCount != 0 {
		_ = checkDB.Close()
		t.Fatalf("expected 0 sessions after orphan cleanup, got %d", orphanCount)
	}
	_ = checkDB.Close()

	dbBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, leaked := range []string{plainAcctSecret, plainLegacySecret, plainWebhookToken} {
		if bytes.Contains(dbBytes, []byte(leaked)) {
			t.Fatalf("plaintext secret %q still present in raw SQLite file after VACUUM", leaked)
		}
	}

	// Reopening with the same cipher key succeeds.
	stAgain, err := Open(dbPath, cipher1)
	if err != nil {
		t.Fatalf("reopen with matching cipher failed: %v", err)
	}
	_ = stAgain.Close()

	// Reopening with a wrong cipher key must fail immediately rather than split-key corrupting state.
	wrongCipher := testCipher(t, 0x99)
	if badStore, err := Open(dbPath, wrongCipher); err == nil {
		_ = badStore.Close()
		t.Fatal("expected Open with mismatched cipher key to fail")
	}
}

func TestDNSAccountUpdatePreservesSecretAndDeleteClearsRefs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	cipher := testCipher(t, 0x24)

	dbPath := filepath.Join(t.TempDir(), "accounts.sqlite3")
	st, err := Open(dbPath, cipher)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	acct1, err := st.CreateDNSAccount(ctx, &DNSAccount{
		Name:            "阿里云主账号",
		Edition:         "cn",
		AccessKeyID:     "LTAI5tKeyOne1234",
		AccessKeySecret: "OriginalSecretOne",
		Email:           "a1@example.com",
		IsDefault:       true,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("CreateDNSAccount 1: %v", err)
	}
	acct2, err := st.CreateDNSAccount(ctx, &DNSAccount{
		Name:            "阿里云国际站",
		Edition:         "intl",
		AccessKeyID:     "LTAI5tKeyTwo5678",
		AccessKeySecret: "OriginalSecretTwo",
		Email:           "a2@example.com",
		IsDefault:       false,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("CreateDNSAccount 2: %v", err)
	}

	var rawBefore string
	if err := st.db.QueryRowContext(ctx, `SELECT access_key_secret FROM dns_accounts WHERE id=?`, acct1.ID).Scan(&rawBefore); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(rawBefore, secretbox.Prefix) {
		t.Fatalf("expected encrypted secret at rest, got %q", rawBefore)
	}

	// Update with empty AccessKeySecret must preserve existing ciphertext verbatim.
	updated, err := st.UpdateDNSAccount(ctx, acct1.ID, &DNSAccount{
		Name:            "阿里云主账号-改名",
		Edition:         "cn",
		AccessKeyID:     acct1.AccessKeyID,
		AccessKeySecret: "",
		Email:           "new@example.com",
		IsDefault:       true,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("UpdateDNSAccount empty secret: %v", err)
	}
	if updated.AccessKeySecret != "OriginalSecretOne" {
		t.Fatalf("expected preserved secret, got %q", updated.AccessKeySecret)
	}
	var rawAfter string
	if err := st.db.QueryRowContext(ctx, `SELECT access_key_secret FROM dns_accounts WHERE id=?`, acct1.ID).Scan(&rawAfter); err != nil {
		t.Fatal(err)
	}
	if rawAfter != rawBefore {
		t.Fatal("expected existing raw ciphertext to be preserved when AccessKeySecret is empty")
	}

	// Update with non-empty AccessKeySecret rotates the encrypted secret.
	rotated, err := st.UpdateDNSAccount(ctx, acct1.ID, &DNSAccount{
		Name:            updated.Name,
		Edition:         "cn",
		AccessKeyID:     acct1.AccessKeyID,
		AccessKeySecret: "RotatedSecret999",
		Email:           updated.Email,
		IsDefault:       true,
		Enabled:         true,
	})
	if err != nil {
		t.Fatalf("UpdateDNSAccount rotated secret: %v", err)
	}
	if rotated.AccessKeySecret != "RotatedSecret999" {
		t.Fatalf("expected rotated secret, got %q", rotated.AccessKeySecret)
	}

	// Bind a certificate and challenge to acct1, then delete acct1.
	cert := &Certificate{
		ID:        NewID(),
		Domains:   []string{"app.example.org"},
		Status:    "valid",
		AutoRenew: true,
		AccountID: acct1.ID,
		SHA256:    strings.Repeat("c", 64),
	}
	if err := st.InsertCertificate(ctx, cert); err != nil {
		t.Fatalf("InsertCertificate: %v", err)
	}
	if err := st.AddChallenge(ctx, Challenge{
		RecordID:      "rec-100",
		CertificateID: cert.ID,
		AccountID:     acct1.ID,
		Zone:          "example.org",
		RR:            "_acme-challenge.app",
		Value:         "tok-val",
	}); err != nil {
		t.Fatalf("AddChallenge: %v", err)
	}

	if err := st.DeleteDNSAccount(ctx, acct1.ID); err != nil {
		t.Fatalf("DeleteDNSAccount: %v", err)
	}

	reloadedCert, err := st.Certificate(ctx, cert.ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedCert.AccountID != "" {
		t.Fatalf("expected certificate AccountID cleared, got %q", reloadedCert.AccountID)
	}

	challenges, err := st.Challenges(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(challenges) != 1 || challenges[0].AccountID != "" {
		t.Fatalf("expected challenge AccountID cleared, got %+v", challenges)
	}

	defAcct, err := st.DefaultDNSAccount(ctx)
	if err != nil {
		t.Fatalf("DefaultDNSAccount: %v", err)
	}
	if defAcct.ID != acct2.ID || !defAcct.IsDefault {
		t.Fatalf("expected acct2 promoted to default, got %+v", defAcct)
	}
}

func TestAPITokenAuthorizationSemantics(t *testing.T) {
	t.Parallel()

	exactTok := &APIToken{Enabled: true, AllowedDomains: []string{"example.net"}}
	for _, target := range []string{"example.net", "EXAMPLE.NET", "  example.net "} {
		if !exactTok.AllowsDomain(target) {
			t.Fatalf("exact token should allow %q", target)
		}
	}
	for _, forbidden := range []string{"*.example.net", "sub.example.net", "a.b.example.net", "evilexample.net", ""} {
		if exactTok.AllowsDomain(forbidden) {
			t.Fatalf("exact token must NOT allow %q", forbidden)
		}
	}

	wildTok := &APIToken{Enabled: true, AllowedDomains: []string{"*.example.net"}}
	for _, target := range []string{"a.example.net", "media.example.net", "*.example.net", "SUB.EXAMPLE.NET"} {
		if !wildTok.AllowsDomain(target) {
			t.Fatalf("wildcard token should allow %q", target)
		}
	}
	for _, forbidden := range []string{"example.net", "a.b.example.net", "*.sub.example.net", "other.net", ""} {
		if wildTok.AllowsDomain(forbidden) {
			t.Fatalf("wildcard token must NOT allow %q", forbidden)
		}
	}

	starTok := &APIToken{Enabled: true, AllowedDomains: []string{"*"}}
	for _, target := range []string{"example.net", "*.example.net", "a.b.example.net"} {
		if !starTok.AllowsDomain(target) {
			t.Fatalf("star token should allow %q", target)
		}
	}
	if starTok.AllowsDomain("") {
		t.Fatal("star token must reject empty target")
	}

	disabledTok := &APIToken{Enabled: false, AllowedDomains: []string{"*"}}
	if disabledTok.AllowsDomain("example.net") || disabledTok.AllowsCertificate([]string{"example.net"}) {
		t.Fatal("disabled token must reject all domains and certificates")
	}

	// Multi-SAN certificate requires EVERY SAN to be authorized.
	apexAndWild := []string{"*.example.net", "example.net"}
	if exactTok.AllowsCertificate(apexAndWild) {
		t.Fatal("exact apex token must not authorize wildcard+apex SAN certificate")
	}
	if wildTok.AllowsCertificate(apexAndWild) {
		t.Fatal("wildcard-only token must not authorize wildcard+apex SAN certificate without apex permission")
	}
	combinedTok := &APIToken{Enabled: true, AllowedDomains: []string{"*.example.net", "example.net"}}
	if !combinedTok.AllowsCertificate(apexAndWild) {
		t.Fatal("combined wildcard+apex token should authorize wildcard+apex SAN certificate")
	}
	if !wildTok.AllowsCertificate([]string{"media.example.net"}) {
		t.Fatal("wildcard token should authorize single-SAN subdomain certificate")
	}
	if wildTok.AllowsCertificate([]string{"media.example.net", "unauth.example.com"}) {
		t.Fatal("wildcard token must reject multi-SAN certificate containing unauthorized SAN")
	}
	if starTok.AllowsCertificate(nil) {
		t.Fatal("empty SAN list must return false")
	}
}

func TestPerIPLoginRateLimiting(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	st, err := Open(filepath.Join(t.TempDir(), "ratelimit.sqlite3"), testCipher(t, 0x33))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	const (
		ip1    = "203.0.113.10"
		ip2    = "198.51.100.25"
		limit  = 3
		window = 15 * time.Minute
	)

	// CheckLoginAllowed alone must not consume quota.
	for i := range 5 {
		ok, err := st.CheckLoginAllowed(ctx, ip1, limit, window)
		if err != nil || !ok {
			t.Fatalf("iter %d: expected CheckLoginAllowed=true without failures, err=%v", i, err)
		}
	}

	for i := range limit {
		if err := st.RecordLoginFailure(ctx, ip1, window); err != nil {
			t.Fatalf("RecordLoginFailure(%d): %v", i, err)
		}
	}
	if err := st.RecordLoginFailure(ctx, ip2, window); err != nil {
		t.Fatal(err)
	}

	if ok, err := st.CheckLoginAllowed(ctx, ip1, limit, window); err != nil || ok {
		t.Fatalf("expected ip1 throttled after %d failures, got ok=%v err=%v", limit, ok, err)
	}
	if ok, err := st.CheckLoginAllowed(ctx, ip2, limit, window); err != nil || !ok {
		t.Fatalf("expected ip2 unaffected by ip1 throttling, got ok=%v err=%v", ok, err)
	}

	st.ClearLoginFailures(ctx, ip1)
	if ok, err := st.CheckLoginAllowed(ctx, ip1, limit, window); err != nil || !ok {
		t.Fatalf("expected ip1 allowed after ClearLoginFailures, got ok=%v err=%v", ok, err)
	}

	// ip2 still has its earlier 1 failure, so 2 more failures should reach limit=3.
	for range 2 {
		if err := st.RecordLoginFailure(ctx, ip2, window); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := st.CheckLoginAllowed(ctx, ip2, limit, window); err != nil || ok {
		t.Fatalf("expected ip2 throttled after reaching limit, got ok=%v err=%v", ok, err)
	}
}

func TestJobsLifecycleRequeueSHA256PruningAndActiveIDs(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	st, err := Open(filepath.Join(t.TempDir(), "jobs.sqlite3"), testCipher(t, 0x55))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	cert1 := &Certificate{
		ID:        NewID(),
		Domains:   []string{"one.example.org"},
		AutoRenew: true,
	}
	job1ID, err := st.CreateCertificateWithJob(ctx, cert1)
	if err != nil {
		t.Fatalf("CreateCertificateWithJob: %v", err)
	}

	cert2 := &Certificate{
		ID:        NewID(),
		Domains:   []string{"two.example.org"},
		Status:    "valid",
		AutoRenew: true,
		NotBefore: "2026-10-01T00:00:00Z",
		NotAfter:  "2027-01-01T00:00:00Z",
		Issuer:    "Let's Encrypt E6",
		SHA256:    strings.Repeat("1", 64),
	}
	if err := st.InsertCertificate(ctx, cert2); err != nil {
		t.Fatalf("InsertCertificate: %v", err)
	}
	job2ID, err := st.QueueJob(ctx, cert2.ID, "renew", "auto")
	if err != nil {
		t.Fatalf("QueueJob: %v", err)
	}

	active, err := st.ActiveJobCertIDs(ctx)
	if err != nil {
		t.Fatalf("ActiveJobCertIDs: %v", err)
	}
	if !active[cert1.ID] || !active[cert2.ID] || len(active) != 2 {
		t.Fatalf("expected both certs active, got %+v", active)
	}

	// Claim job1 ("queued" -> "running", cert1 -> "issuing"), then graceful RequeueJob.
	claimed1, err := st.ClaimJob(ctx)
	if err != nil || claimed1 == nil || claimed1.ID != job1ID {
		t.Fatalf("ClaimJob 1: got %+v, err=%v", claimed1, err)
	}
	if c1, _ := st.Certificate(ctx, cert1.ID); c1.Status != "issuing" {
		t.Fatalf("expected cert1 status=issuing, got %q", c1.Status)
	}
	if err := st.RequeueJob(ctx, claimed1, "服务重启，任务已重新入队等待续跑"); err != nil {
		t.Fatalf("RequeueJob 1: %v", err)
	}
	reloadedJob1, err := st.Job(ctx, job1ID)
	if err != nil {
		t.Fatal(err)
	}
	if reloadedJob1.Status != "queued" || reloadedJob1.StartedAt != "" || !strings.Contains(reloadedJob1.Output, "[提示] 服务重启") {
		t.Fatalf("unexpected requeued job1: %+v", reloadedJob1)
	}
	if c1, _ := st.Certificate(ctx, cert1.ID); c1.Status != "queued" {
		t.Fatalf("expected cert1 restored to status=queued, got %q", c1.Status)
	}

	// Claim next job and finish both; also verify renewing cert keeps status=renewing on RequeueJob.
	for i := range 2 {
		j, err := st.ClaimJob(ctx)
		if err != nil || j == nil {
			t.Fatalf("ClaimJob loop %d: %+v, err=%v", i, j, err)
		}
		if j.ID == job2ID {
			if err := st.RequeueJob(ctx, j, "测试续期重入队"); err != nil {
				t.Fatalf("RequeueJob 2: %v", err)
			}
			if c2, _ := st.Certificate(ctx, cert2.ID); c2.Status != "renewing" {
				t.Fatalf("expected renewing cert to remain renewing, got %q", c2.Status)
			}
			j, err = st.ClaimJob(ctx)
			if err != nil || j == nil {
				t.Fatalf("re-claim job2: %+v, err=%v", j, err)
			}
		}
		sha := strings.Repeat("f", 64)
		if err := st.FinishJob(ctx, j, &IssuedInfo{
			NotBefore: "2026-11-11T00:00:00Z",
			NotAfter:  "2027-02-09T00:00:00Z",
			Issuer:    "Let's Encrypt E6",
			SHA256:    sha,
		}, ""); err != nil {
			t.Fatalf("FinishJob(%s): %v", j.ID, err)
		}
	}

	if c1, err := st.Certificate(ctx, cert1.ID); err != nil || c1.SHA256 != strings.Repeat("f", 64) || c1.Status != "valid" {
		t.Fatalf("expected cert1 valid with SHA256 persisted, got %+v err=%v", c1, err)
	}
	if active, err := st.ActiveJobCertIDs(ctx); err != nil || len(active) != 0 {
		t.Fatalf("expected 0 active certs, got %+v err=%v", active, err)
	}

	// Test RecoverInterrupted.
	if _, err := st.QueueJob(ctx, cert1.ID, "renew", "manual"); err != nil {
		t.Fatal(err)
	}
	interrupted, err := st.ClaimJob(ctx)
	if err != nil || interrupted == nil {
		t.Fatalf("ClaimJob interrupted: %+v err=%v", interrupted, err)
	}
	if err := st.RecoverInterrupted(ctx); err != nil {
		t.Fatalf("RecoverInterrupted: %v", err)
	}
	if recJob, err := st.Job(ctx, interrupted.ID); err != nil || recJob.Status != "failed" {
		t.Fatalf("expected interrupted job failed, got %+v err=%v", recJob, err)
	}

	// Seed 505 historical completed jobs + keep 1 active queued job on cert2, then finish a job on cert1
	// to verify FinishJob prunes completed jobs to 500 without touching active jobs.
	tx, err := st.db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 505 {
		ts := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(i) * time.Minute).Format(time.RFC3339)
		if _, err := tx.ExecContext(ctx, `INSERT INTO jobs(id,certificate_id,kind,status,trigger,created_at,finished_at,output)
			VALUES(?,?,?,?,?,?,?,?)`, fmt.Sprintf("hist-%04d", i), cert1.ID, "renew", "succeeded", "auto", ts, ts, ""); err != nil {
			_ = tx.Rollback()
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}

	keptQueuedID, err := st.QueueJob(ctx, cert2.ID, "renew", "manual")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.QueueJob(ctx, cert1.ID, "renew", "manual"); err != nil {
		t.Fatal(err)
	}
	runJob, err := st.ClaimJob(ctx)
	if err != nil || runJob == nil {
		t.Fatalf("ClaimJob for prune test: %+v err=%v", runJob, err)
	}
	// ClaimJob claims oldest queued (keptQueuedID on cert2); finish it while cert1 remains queued!
	if runJob.ID != keptQueuedID {
		t.Fatalf("expected oldest queued job %s claimed first, got %s", keptQueuedID, runJob.ID)
	}
	if err := st.FinishJob(ctx, runJob, &IssuedInfo{
		NotBefore: "2026-11-11T00:00:00Z",
		NotAfter:  "2027-02-09T00:00:00Z",
		Issuer:    "Let's Encrypt E6",
		SHA256:    strings.Repeat("d", 64),
	}, ""); err != nil {
		t.Fatalf("FinishJob prune trigger: %v", err)
	}

	var finishedCount, queuedCount int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE status IN ('succeeded','failed')`).Scan(&finishedCount); err != nil {
		t.Fatal(err)
	}
	if finishedCount != 500 {
		t.Fatalf("expected finished jobs pruned to 500, got %d", finishedCount)
	}
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM jobs WHERE status='queued'`).Scan(&queuedCount); err != nil {
		t.Fatal(err)
	}
	if queuedCount != 1 {
		t.Fatalf("expected queued job preserved (1), got %d", queuedCount)
	}
}

func TestSessionInfoRejectsInvalidAndCleansUp(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	st, err := Open(filepath.Join(t.TempDir(), "sessions.sqlite3"), testCipher(t, 0x66))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	admin, err := st.CreateUser(ctx, &User{
		Username:     "admin",
		DisplayName:  "Admin",
		PasswordHash: "hash1",
		Role:         "admin",
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	op, err := st.CreateUser(ctx, &User{
		Username:     "operator1",
		DisplayName:  "Operator",
		PasswordHash: "hash2",
		Role:         "operator",
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}

	tok, csrf, err := st.CreateUserSession(ctx, op, "10.0.0.1", "GoTest", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if u, gotCSRF, ok := st.SessionInfo(ctx, tok); !ok || u.ID != op.ID || gotCSRF != csrf {
		t.Fatalf("expected valid session for op, got u=%+v csrf=%q ok=%v", u, gotCSRF, ok)
	}

	// Disable user directly in DB so session row still exists; SessionInfo must reject AND delete the row.
	if _, err := st.db.ExecContext(ctx, `UPDATE users SET enabled=0 WHERE id=?`, op.ID); err != nil {
		t.Fatal(err)
	}
	if u, _, ok := st.SessionInfo(ctx, tok); ok || u != nil {
		t.Fatalf("expected disabled user session rejected, got %+v", u)
	}
	var count int
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashToken(tok)).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("expected disabled user's session row deleted, got %d", count)
	}

	// Orphan session (user_id='') and expired session must both be rejected and deleted.
	orphanRaw := "orphan-raw-token"
	if _, err := st.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,username,csrf,expires_at) VALUES(?,?,?,?,?)`,
		hashToken(orphanRaw), "", "admin", "c1", time.Now().Add(time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := st.SessionInfo(ctx, orphanRaw); ok {
		t.Fatal("expected orphan session rejected")
	}
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashToken(orphanRaw)).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expected orphan session deleted, count=%d err=%v", count, err)
	}

	expiredRaw := "expired-raw-token"
	if _, err := st.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,username,csrf,expires_at) VALUES(?,?,?,?,?)`,
		hashToken(expiredRaw), admin.ID, admin.Username, "c2", time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := st.SessionInfo(ctx, expiredRaw); ok {
		t.Fatal("expected expired session rejected")
	}
	if err := st.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM sessions WHERE token_hash=?`, hashToken(expiredRaw)).Scan(&count); err != nil || count != 0 {
		t.Fatalf("expected expired session deleted, count=%d err=%v", count, err)
	}
}

func TestAuditLogsFilterAndLikeEscaping(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	st, err := Open(filepath.Join(t.TempDir(), "audit.sqlite3"), testCipher(t, 0x77))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	st.AddAudit(ctx, "admin", "10.0.0.1", "user.login", "admin", "100% ok")
	st.AddAudit(ctx, "admin", "10.0.0.2", "user.login_failed", "bob", "1000 ok")
	st.AddAudit(ctx, "token:edge", "203.0.113.5", "cert.pull", "a.example.net", `path=C:\certs\key`)
	st.AddAudit(ctx, "ops", "10.0.0.3", "user_custom", "t1", "exact_under")
	st.AddAudit(ctx, "ops", "10.0.0.4", "userXcustom", "t2", "exactXunder")

	byPrefix, err := st.AuditLogs(ctx, AuditFilter{Action: "user."})
	if err != nil {
		t.Fatalf("AuditLogs prefix: %v", err)
	}
	if len(byPrefix) != 2 {
		t.Fatalf("expected 2 user.* logs, got %d: %+v", len(byPrefix), byPrefix)
	}

	byEscapedAction, err := st.AuditLogs(ctx, AuditFilter{Action: "user_"})
	if err != nil {
		t.Fatalf("AuditLogs escaped _: %v", err)
	}
	if len(byEscapedAction) != 1 || byEscapedAction[0].Action != "user_custom" {
		t.Fatalf("expected only user_custom, got %+v", byEscapedAction)
	}

	byPercent, err := st.AuditLogs(ctx, AuditFilter{Keyword: "100%"})
	if err != nil {
		t.Fatalf("AuditLogs escaped %%: %v", err)
	}
	if len(byPercent) != 1 || byPercent[0].Detail != "100% ok" {
		t.Fatalf("expected only '100%% ok', got %+v", byPercent)
	}

	byUnderscore, err := st.AuditLogs(ctx, AuditFilter{Keyword: "exact_"})
	if err != nil {
		t.Fatalf("AuditLogs escaped _ keyword: %v", err)
	}
	if len(byUnderscore) != 1 || byUnderscore[0].Detail != "exact_under" {
		t.Fatalf("expected only 'exact_under', got %+v", byUnderscore)
	}

	byBackslash, err := st.AuditLogs(ctx, AuditFilter{Keyword: `C:\certs`})
	if err != nil {
		t.Fatalf("AuditLogs escaped \\ keyword: %v", err)
	}
	if len(byBackslash) != 1 || byBackslash[0].Action != "cert.pull" {
		t.Fatalf("expected cert.pull log for backslash search, got %+v", byBackslash)
	}

	byIP, err := st.AuditLogs(ctx, AuditFilter{Keyword: "203.0.113.5"})
	if err != nil || len(byIP) != 1 {
		t.Fatalf("expected 1 match by IP, got %+v err=%v", byIP, err)
	}

	limited, err := st.AuditLogs(ctx, AuditFilter{Limit: 2})
	if err != nil || len(limited) != 2 {
		t.Fatalf("expected limit=2 respected, got %d err=%v", len(limited), err)
	}
}

func TestUsersAndAPITokensCRUD(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	st, err := Open(filepath.Join(t.TempDir(), "crud.sqlite3"), testCipher(t, 0x88))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	admin, err := st.CreateUser(ctx, &User{
		Username:     "admin",
		DisplayName:  "Admin",
		PasswordHash: "hash-initial",
		Role:         "admin",
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.CreateUser(ctx, &User{
		Username:     "ADMIN",
		PasswordHash: "hash-dup",
		Role:         "admin",
		Enabled:      true,
	}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate, got %v", err)
	}
	if err := st.DeleteUser(ctx, admin.ID); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin on delete, got %v", err)
	}
	if _, err := st.UpdateUser(ctx, admin.ID, "Admin", "operator", true, ""); !errors.Is(err, ErrLastAdmin) {
		t.Fatalf("expected ErrLastAdmin on demote, got %v", err)
	}

	// Updating admin password must NOT write legacy settings('password_hash').
	if _, err := st.UpdateUser(ctx, admin.ID, "Admin2", "admin", true, "hash-rotated"); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	if legacyPW, err := st.Setting(ctx, "password_hash"); err != nil || legacyPW != "" {
		t.Fatalf("expected no legacy password_hash in settings, got %q err=%v", legacyPW, err)
	}

	tok, plain, err := st.CreateAPIToken(ctx, "edge-node", []string{"*.example.net"})
	if err != nil {
		t.Fatalf("CreateAPIToken: %v", err)
	}
	if _, _, err := st.CreateAPIToken(ctx, "edge-node", []string{"*"}); !errors.Is(err, ErrDuplicate) {
		t.Fatalf("expected ErrDuplicate on duplicate token name, got %v", err)
	}
	authed, ok := st.AuthenticateAPIToken(ctx, plain, "198.51.100.88")
	if !ok || authed.ID != tok.ID || authed.LastUsedIP != "198.51.100.88" {
		t.Fatalf("AuthenticateAPIToken failed: ok=%v tok=%+v", ok, authed)
	}
	updatedTok, err := st.UpdateAPIToken(ctx, tok.ID, "edge-node-v2", []string{"a.example.net"}, false)
	if err != nil || updatedTok.Enabled || updatedTok.Name != "edge-node-v2" {
		t.Fatalf("UpdateAPIToken failed: %+v err=%v", updatedTok, err)
	}
	if _, ok := st.AuthenticateAPIToken(ctx, plain, "198.51.100.88"); ok {
		t.Fatal("disabled API token must not authenticate")
	}
	if err := st.DeleteAPIToken(ctx, tok.ID); err != nil {
		t.Fatalf("DeleteAPIToken: %v", err)
	}
	if _, err := st.APIToken(ctx, tok.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
}
