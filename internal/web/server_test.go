package web_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"certdns/internal/alidns"
	"certdns/internal/certx"
	"certdns/internal/issuer"
	"certdns/internal/pwhash"
	"certdns/internal/secretbox"
	"certdns/internal/store"
	"certdns/internal/web"
)

func makeTestCertWithExpiry(t *testing.T, notBefore, notAfter time.Time, domains ...string) map[string][]byte {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: domains[0]},
		Issuer:       pkix.Name{CommonName: "R3", Organization: []string{"Let's Encrypt"}},
		DNSNames:     domains,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return map[string][]byte{
		"cert.pem":      certPEM,
		"chain.pem":     certPEM,
		"fullchain.pem": append(append([]byte{}, certPEM...), certPEM...),
		"privkey.pem":   keyPEM,
	}
}

func makeTestCert(t *testing.T, domains ...string) map[string][]byte {
	t.Helper()
	return makeTestCertWithExpiry(t, time.Now().Add(-time.Hour), time.Now().Add(89*24*time.Hour), domains...)
}

func seedCertRecord(t *testing.T, ctx context.Context, st *store.Store, mgr *issuer.Manager, id, status string, files map[string][]byte, domains ...string) certx.Metadata {
	t.Helper()
	if err := mgr.WriteFiles(id, files); err != nil {
		t.Fatal(err)
	}
	leaf, err := certx.InspectLeaf(files["cert.pem"])
	if err != nil {
		t.Fatal(err)
	}
	meta := certx.ExtractMetadata(leaf, "EC256")
	if err := st.InsertCertificate(ctx, &store.Certificate{
		ID:        id,
		Domains:   domains,
		Status:    status,
		AutoRenew: true,
		KeyType:   meta.KeyType,
		Source:    "acme",
		NotBefore: meta.NotBefore,
		NotAfter:  meta.NotAfter,
		Issuer:    meta.Issuer,
		SHA256:    meta.SHA256,
	}); err != nil {
		t.Fatal(err)
	}
	return meta
}

func openTestStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	tmp := t.TempDir()
	cipher, err := secretbox.NewFromKey(bytes.Repeat([]byte{0x5a}, 32))
	if err != nil {
		t.Fatal(err)
	}
	st, err := store.Open(filepath.Join(tmp, "test.sqlite3"), cipher)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	return st, tmp
}

func seedAdminUser(t *testing.T, ctx context.Context, st *store.Store, password string) *store.User {
	t.Helper()
	pwHash, err := pwhash.Hash(password)
	if err != nil {
		t.Fatal(err)
	}
	u, err := st.CreateUser(ctx, &store.User{
		Username:     "admin",
		DisplayName:  "系统管理员",
		PasswordHash: pwHash,
		Role:         "admin",
		Enabled:      true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestEndToEndMultiUserMultiAccountAndDNS(t *testing.T) {
	ctx := context.Background()
	st, tmp := openTestStore(t)
	seedAdminUser(t, ctx, st, "correct-horse-battery")

	var (
		mu                 sync.Mutex
		actionCounts       = map[string]int{}
		curRemark          = "mgmt"
		lastHasRemarkParam bool
		lastAddedType      string
		lastAddedValue     string
	)
	longTXT := strings.Repeat("a", 300)

	// Mock AliDNS server differentiating China vs International account keys and tracking mutations.
	fakeAli := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		action := r.Form.Get("Action")
		keyID := r.Form.Get("AccessKeyId")

		mu.Lock()
		actionCounts[action]++
		rem := curRemark
		mu.Unlock()

		switch action {
		case "DescribeDomains":
			if strings.Contains(keyID, "Intl") {
				if r.Form.Get("RegionId") != "ap-southeast-1" {
					t.Errorf("expected ap-southeast-1 for international account, got %s", r.Form.Get("RegionId"))
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"TotalCount": 1,
					"Domains": map[string]any{
						"Domain": []map[string]any{{"DomainName": "global-app.io"}},
					},
				})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"TotalCount": 2,
				"Domains": map[string]any{
					"Domain": []map[string]any{
						{"DomainName": "example.org"},
						{"DomainName": "service.org"},
					},
				},
			})
		case "DescribeDomainRecords":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"TotalCount": 3,
				"DomainRecords": map[string]any{
					"Record": []map[string]any{
						{
							"RecordId":   "998877",
							"DomainName": r.Form.Get("DomainName"),
							"RR":         "cert",
							"Type":       "A",
							"Value":      "203.0.113.10",
							"TTL":        600,
							"Line":       "default",
							"Status":     "ENABLE",
							"Remark":     rem,
						},
						{
							"RecordId":   "998878",
							"DomainName": r.Form.Get("DomainName"),
							"RR":         "_sip._tcp",
							"Type":       "SRV",
							"Value":      "0 5 5060 sip.example.org",
							"TTL":        600,
							"Line":       "default",
							"Status":     "ENABLE",
							"Remark":     "sip",
						},
						{
							"RecordId":   "998879",
							"DomainName": r.Form.Get("DomainName"),
							"RR":         "dkim._domainkey",
							"Type":       "TXT",
							"Value":      longTXT,
							"TTL":        600,
							"Line":       "default",
							"Status":     "ENABLE",
							"Remark":     "dkim",
						},
					},
				},
			})
		case "DescribeDomainRecordInfo":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"RecordId":   r.Form.Get("RecordId"),
				"DomainName": "example.org",
				"RR":         "cert",
				"Type":       "A",
				"Value":      "203.0.113.10",
				"TTL":        600,
				"Line":       "default",
				"Remark":     rem,
			})
		case "AddDomainRecord":
			mu.Lock()
			lastAddedType = r.Form.Get("Type")
			lastAddedValue = r.Form.Get("Value")
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"RecordId": "112233"})
		case "UpdateDomainRecordRemark":
			mu.Lock()
			_, lastHasRemarkParam = r.Form["Remark"]
			curRemark = r.Form.Get("Remark")
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{"RecordId": r.Form.Get("RecordId")})
		case "UpdateDomainRecord", "DeleteDomainRecord", "SetDomainRecordStatus":
			_ = json.NewEncoder(w).Encode(map[string]any{"RecordId": r.Form.Get("RecordId")})
		}
	}))
	defer fakeAli.Close()

	defAcct, err := st.CreateDNSAccount(ctx, &store.DNSAccount{
		Name:            "默认国内账户",
		Edition:         alidns.EditionCustom,
		Endpoint:        fakeAli.URL,
		AccessKeyID:     "LTAI5tTestKey123",
		AccessKeySecret: "SecretValue123456",
		Email:           "ops@example.org",
		IsDefault:       true,
		Enabled:         true,
	})
	if err != nil {
		t.Fatal(err)
	}

	mgr := issuer.New(st, tmp, filepath.Join(tmp, "tls"), "cert.example.org")

	// Seed a valid management certificate covering *.example.org + example.org.
	mgmtID := "d0e5a7e789e8465487aca6f0223a4a5c"
	seedCertRecord(t, ctx, st, mgr, mgmtID, "valid", makeTestCert(t, "*.example.org", "example.org"), "*.example.org", "example.org")
	if err := mgr.SyncTLS(ctx); err != nil {
		t.Fatal(err)
	}

	srv := &web.Server{Store: st, Manager: mgr, InsecureCookie: true}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	loginAs := func(username, password string) ([]*http.Cookie, string, string) {
		loginBody, _ := json.Marshal(map[string]string{"username": username, "password": password})
		req, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(loginBody))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Requested-With", "certdns")
		resp, err := http.DefaultClient.Do(req)
		if err != nil || resp.StatusCode != 200 {
			t.Fatalf("login failed for %s: %v", username, resp)
		}
		defer resp.Body.Close()
		var loginRes struct {
			CSRF     string `json:"csrf"`
			Hostname string `json:"hostname"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&loginRes)
		return resp.Cookies(), loginRes.CSRF, loginRes.Hostname
	}

	// 1. Admin login with empty username fallback works and returns hostname.
	cookies, csrf, loginHost := loginAs("", "correct-horse-battery")
	if loginHost != "cert.example.org" {
		t.Fatalf("expected hostname cert.example.org in login response, got %q", loginHost)
	}

	doReq := func(cks []*http.Cookie, token, method, path string, body any) *http.Response {
		var rdr *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rdr = bytes.NewReader(b)
		} else {
			rdr = bytes.NewReader(nil)
		}
		rq, _ := http.NewRequest(method, ts.URL+path, rdr)
		for _, ck := range cks {
			rq.AddCookie(ck)
		}
		if body != nil {
			rq.Header.Set("Content-Type", "application/json")
		}
		if method != "GET" && method != "HEAD" {
			rq.Header.Set("X-CSRF-Token", token)
		}
		rs, err := http.DefaultClient.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}

	// 2. Add an Alibaba Cloud International account and verify multi-account zone aggregation.
	addAcctResp := doReq(cookies, csrf, "POST", "/api/accounts", map[string]any{
		"name":              "AliCloud International SG",
		"edition":           "intl",
		"endpoint":          fakeAli.URL,
		"access_key_id":     "LTAI5tIntlAccount99",
		"access_key_secret": "IntlSecretKey998877",
		"email":             "intl@global-app.io",
	})
	if addAcctResp.StatusCode != 201 {
		t.Fatalf("expected 201 creating international account, got %d", addAcctResp.StatusCode)
	}
	_ = addAcctResp.Body.Close()

	zResp := doReq(cookies, csrf, "GET", "/api/dns/zones?refresh=1", nil)
	if zResp.StatusCode != 200 {
		t.Fatalf("zones failed: %d", zResp.StatusCode)
	}
	var zData struct {
		Zones []string           `json:"zones"`
		Items []issuer.ZoneOwner `json:"items"`
	}
	_ = json.NewDecoder(zResp.Body).Decode(&zData)
	_ = zResp.Body.Close()
	if len(zData.Zones) != 3 {
		t.Fatalf("expected 3 aggregated zones across CN + Intl accounts, got %v", zData.Zones)
	}

	// 3. Create operator and viewer users; verify RBAC & non-admin AccessKeyID redaction across all 3 endpoints.
	opResp := doReq(cookies, csrf, "POST", "/api/users", map[string]any{
		"username":     "opsuser",
		"display_name": "运维专员",
		"password":     "operator-pass-123",
		"role":         "operator",
	})
	if opResp.StatusCode != 201 {
		t.Fatalf("expected 201 creating operator user, got %d", opResp.StatusCode)
	}
	_ = opResp.Body.Close()

	uResp := doReq(cookies, csrf, "POST", "/api/users", map[string]any{
		"username":     "auditor",
		"display_name": "只读审计",
		"password":     "auditor-pass-123",
		"role":         "viewer",
	})
	if uResp.StatusCode != 201 {
		t.Fatalf("expected 201 creating viewer user, got %d", uResp.StatusCode)
	}
	_ = uResp.Body.Close()

	opCookies, opCSRF, _ := loginAs("opsuser", "operator-pass-123")
	vCookies, vCSRF, _ := loginAs("auditor", "auditor-pass-123")

	// Admin sees full AccessKeyID; operator and viewer see empty AccessKeyID + preserved MaskedKeyID.
	adminAcctResp := doReq(cookies, csrf, "GET", "/api/accounts", nil)
	var adminAccts struct {
		Accounts []store.DNSAccount `json:"accounts"`
	}
	_ = json.NewDecoder(adminAcctResp.Body).Decode(&adminAccts)
	_ = adminAcctResp.Body.Close()
	if len(adminAccts.Accounts) == 0 || adminAccts.Accounts[0].AccessKeyID == "" {
		t.Fatalf("expected admin to see full AccessKeyID, got %+v", adminAccts.Accounts)
	}

	for _, roleCase := range []struct {
		name string
		cks  []*http.Cookie
		tok  string
	}{
		{"operator", opCookies, opCSRF},
		{"viewer", vCookies, vCSRF},
	} {
		listRes := doReq(roleCase.cks, roleCase.tok, "GET", "/api/accounts", nil)
		var payload struct {
			Accounts []store.DNSAccount `json:"accounts"`
		}
		_ = json.NewDecoder(listRes.Body).Decode(&payload)
		_ = listRes.Body.Close()
		for _, a := range payload.Accounts {
			if a.AccessKeyID != "" || a.MaskedKeyID == "" {
				t.Fatalf("%s listAccounts must redact AccessKeyID and keep MaskedKeyID, got %+v", roleCase.name, a)
			}
		}
	}

	// Operator testAccount and syncAllAccounts must also redact AccessKeyID.
	testAcctRes := doReq(opCookies, opCSRF, "POST", "/api/accounts/"+defAcct.ID+"/test", map[string]any{})
	if testAcctRes.StatusCode != 200 {
		t.Fatalf("operator testAccount failed: %d", testAcctRes.StatusCode)
	}
	var testAcctPayload struct {
		Account store.DNSAccount `json:"account"`
	}
	_ = json.NewDecoder(testAcctRes.Body).Decode(&testAcctPayload)
	_ = testAcctRes.Body.Close()
	if testAcctPayload.Account.AccessKeyID != "" || testAcctPayload.Account.MaskedKeyID == "" {
		t.Fatalf("operator testAccount leaked AccessKeyID: %+v", testAcctPayload.Account)
	}

	syncAllRes := doReq(opCookies, opCSRF, "POST", "/api/accounts/sync-all", map[string]any{})
	if syncAllRes.StatusCode != 200 {
		t.Fatalf("operator syncAllAccounts failed: %d", syncAllRes.StatusCode)
	}
	var syncAllPayload struct {
		Accounts []store.DNSAccount `json:"accounts"`
	}
	_ = json.NewDecoder(syncAllRes.Body).Decode(&syncAllPayload)
	_ = syncAllRes.Body.Close()
	for _, a := range syncAllPayload.Accounts {
		if a.AccessKeyID != "" || a.MaskedKeyID == "" {
			t.Fatalf("operator syncAllAccounts leaked AccessKeyID: %+v", a)
		}
	}

	// Viewer can list certs, but cannot download private keys or delete records.
	if r := doReq(vCookies, vCSRF, "GET", "/api/certificates", nil); r.StatusCode != 200 {
		t.Fatalf("viewer should list certs, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	if r := doReq(vCookies, vCSRF, "GET", "/api/certificates/"+mgmtID+"/download", nil); r.StatusCode != 403 {
		t.Fatalf("viewer must be forbidden from downloading private keys, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	if r := doReq(vCookies, vCSRF, "DELETE", "/api/dns/records/998877", map[string]string{"zone": "example.org"}); r.StatusCode != 403 {
		t.Fatalf("viewer must be forbidden from deleting DNS records, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}

	// 4. Custom PEM certificate upload, updateCertificate validation, and Nginx download.
	upFiles := makeTestCert(t, "imported.example.com")
	upResp := doReq(cookies, csrf, "POST", "/api/certificates/upload", map[string]string{
		"fullchain_pem": string(upFiles["fullchain.pem"]),
		"privkey_pem":   string(upFiles["privkey.pem"]),
		"remark":        "External cert",
	})
	if upResp.StatusCode != 201 {
		t.Fatalf("expected 201 uploading cert, got %d", upResp.StatusCode)
	}
	var upData struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(upResp.Body).Decode(&upData)
	_ = upResp.Body.Close()

	// Uploaded cert rejects auto_renew=true or non-empty account_id.
	if r := doReq(cookies, csrf, "PUT", "/api/certificates/"+upData.ID, map[string]any{"auto_renew": true}); r.StatusCode != 400 {
		t.Fatalf("expected 400 enabling auto_renew on upload cert, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	if r := doReq(cookies, csrf, "PUT", "/api/certificates/"+upData.ID, map[string]any{"account_id": defAcct.ID}); r.StatusCode != 400 {
		t.Fatalf("expected 400 binding account_id on upload cert, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	// ACME cert rejects nonexistent account_id, succeeds with valid account_id and logs cert.update.
	if r := doReq(cookies, csrf, "PUT", "/api/certificates/"+mgmtID, map[string]any{"account_id": "00000000000000000000000000000000"}); r.StatusCode != 400 {
		t.Fatalf("expected 400 for nonexistent account_id, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	if r := doReq(cookies, csrf, "PUT", "/api/certificates/"+mgmtID, map[string]any{
		"account_id": defAcct.ID,
		"remark":     "核心入口证书",
	}); r.StatusCode != 200 {
		t.Fatalf("expected 200 updating ACME cert meta, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}

	dlNginx := doReq(cookies, csrf, "GET", "/api/certificates/"+mgmtID+"/download?format=nginx", nil)
	if dlNginx.StatusCode != 200 {
		t.Fatalf("expected 200 downloading nginx bundle, got %d", dlNginx.StatusCode)
	}
	_ = dlNginx.Body.Close()

	// 5. DNS non-MX remark-only update & remark clear must NOT invoke UpdateDomainRecord.
	mu.Lock()
	beforeUpdateCalls := actionCounts["UpdateDomainRecord"]
	beforeRemarkCalls := actionCounts["UpdateDomainRecordRemark"]
	mu.Unlock()

	remOnlyRes := doReq(cookies, csrf, "PUT", "/api/dns/records/998877", map[string]any{
		"zone":   "example.org",
		"rr":     "cert",
		"type":   "A",
		"value":  "203.0.113.10",
		"ttl":    600,
		"remark": "updated-mgmt-note",
	})
	if remOnlyRes.StatusCode != 200 {
		t.Fatalf("remark-only updateRecord failed: %d", remOnlyRes.StatusCode)
	}
	_ = remOnlyRes.Body.Close()

	mu.Lock()
	if actionCounts["UpdateDomainRecord"] != beforeUpdateCalls {
		t.Fatalf("expected UpdateDomainRecord NOT called on remark-only edit, got %d -> %d", beforeUpdateCalls, actionCounts["UpdateDomainRecord"])
	}
	if actionCounts["UpdateDomainRecordRemark"] != beforeRemarkCalls+1 || !lastHasRemarkParam || curRemark != "updated-mgmt-note" {
		t.Fatalf("expected UpdateDomainRecordRemark with Remark='updated-mgmt-note', got count=%d hasParam=%v cur=%q",
			actionCounts["UpdateDomainRecordRemark"], lastHasRemarkParam, curRemark)
	}
	mu.Unlock()

	// Clearing remark via updateRecord omits Remark param and still skips UpdateDomainRecord.
	clearRemRes := doReq(cookies, csrf, "PUT", "/api/dns/records/998877", map[string]any{
		"zone":   "example.org",
		"rr":     "cert",
		"type":   "A",
		"value":  "203.0.113.10",
		"ttl":    600,
		"remark": "",
	})
	if clearRemRes.StatusCode != 200 {
		t.Fatalf("remark-clear updateRecord failed: %d", clearRemRes.StatusCode)
	}
	_ = clearRemRes.Body.Close()

	mu.Lock()
	if actionCounts["UpdateDomainRecord"] != beforeUpdateCalls {
		t.Fatalf("expected UpdateDomainRecord NOT called on remark clear, got %d", actionCounts["UpdateDomainRecord"])
	}
	if actionCounts["UpdateDomainRecordRemark"] != beforeRemarkCalls+2 || lastHasRemarkParam || curRemark != "" {
		t.Fatalf("expected UpdateDomainRecordRemark without Remark param to clear remark, got count=%d hasParam=%v cur=%q",
			actionCounts["UpdateDomainRecordRemark"], lastHasRemarkParam, curRemark)
	}
	mu.Unlock()

	// Dedicated PUT /api/dns/records/{id}/remark validation (control chars & >100 runes rejected).
	if r := doReq(cookies, csrf, "PUT", "/api/dns/records/998877/remark", map[string]any{
		"zone":   "example.org",
		"remark": "bad\ninjection",
	}); r.StatusCode != 400 {
		t.Fatalf("expected 400 on newline in remark, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	if r := doReq(cookies, csrf, "PUT", "/api/dns/records/998877/remark", map[string]any{
		"zone":   "example.org",
		"remark": strings.Repeat("备", 101),
	}); r.StatusCode != 400 {
		t.Fatalf("expected 400 on >100 rune remark, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	if r := doReq(cookies, csrf, "PUT", "/api/dns/records/998877/remark", map[string]any{
		"zone":   "example.org",
		"remark": "独立备注修改",
	}); r.StatusCode != 200 {
		t.Fatalf("expected 200 on valid remark update, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}

	// CAA auto-quoting & TXT >512 validation.
	if r := doReq(cookies, csrf, "POST", "/api/dns/records", map[string]any{
		"zone":  "example.org",
		"rr":    "@",
		"type":  "CAA",
		"value": "0 issue letsencrypt.org",
	}); r.StatusCode != 201 {
		t.Fatalf("expected 201 adding CAA record, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	mu.Lock()
	if lastAddedType != "CAA" || lastAddedValue != `0 issue "letsencrypt.org"` {
		t.Fatalf("expected auto-quoted CAA value, got %s %q", lastAddedType, lastAddedValue)
	}
	mu.Unlock()

	if r := doReq(cookies, csrf, "POST", "/api/dns/records", map[string]any{
		"zone":  "example.org",
		"rr":    "_txt",
		"type":  "TXT",
		"value": strings.Repeat("x", 513),
	}); r.StatusCode != 400 {
		t.Fatalf("expected 400 on TXT > 512 chars, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}

	// DNS status toggle & BIND zone export (SRV trailing dot + >255 TXT split + dns.export audit).
	if r := doReq(cookies, csrf, "POST", "/api/dns/records/998877/status", map[string]any{"zone": "example.org", "enabled": false}); r.StatusCode != 200 {
		t.Fatalf("status toggle failed: %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	expRes := doReq(cookies, csrf, "GET", "/api/dns/export?zone=example.org", nil)
	if expRes.StatusCode != 200 {
		t.Fatalf("zone export failed: %d", expRes.StatusCode)
	}
	zoneTextBytes, _ := io.ReadAll(expRes.Body)
	_ = expRes.Body.Close()
	zoneText := string(zoneTextBytes)
	if !strings.Contains(zoneText, "0 5 5060 sip.example.org.") {
		t.Fatalf("expected SRV target trailing dot in zone export, got:\n%s", zoneText)
	}
	expectedSplitTXT := `"` + strings.Repeat("a", 255) + `" "` + strings.Repeat("a", 45) + `"`
	if !strings.Contains(zoneText, expectedSplitTXT) {
		t.Fatalf("expected >255-byte TXT split into RFC 1035 chunks in zone export, got:\n%s", zoneText)
	}

	// 6. Verify audit filtering (?action=dns.export).
	auditResp := doReq(cookies, csrf, "GET", "/api/audit?action=dns.export&limit=10", nil)
	if auditResp.StatusCode != 200 {
		t.Fatalf("audit logs failed: %d", auditResp.StatusCode)
	}
	var auditPayload struct {
		Logs []store.AuditLog `json:"logs"`
	}
	_ = json.NewDecoder(auditResp.Body).Decode(&auditPayload)
	_ = auditResp.Body.Close()
	if len(auditPayload.Logs) != 1 || auditPayload.Logs[0].Action != "dns.export" {
		t.Fatalf("expected 1 dns.export audit log, got %+v", auditPayload.Logs)
	}
}

func TestPullAPISecurityRenewalExpiryETagAndAudit(t *testing.T) {
	ctx := context.Background()
	st, tmp := openTestStore(t)
	seedAdminUser(t, ctx, st, "correct-horse-battery")
	mgr := issuer.New(st, tmp, filepath.Join(tmp, "tls"), "cert.example.org")

	now := time.Now()
	// 1) Wildcard + root multi-SAN cert
	wildID := "11111111111111111111111111111111"
	seedCertRecord(t, ctx, st, mgr, wildID, "valid",
		makeTestCertWithExpiry(t, now.Add(-time.Hour), now.Add(60*24*time.Hour), "*.example.org", "example.org"),
		"*.example.org", "example.org")

	// 2) Multi-SAN exact cert
	multiID := "22222222222222222222222222222222"
	seedCertRecord(t, ctx, st, mgr, multiID, "valid",
		makeTestCertWithExpiry(t, now.Add(-time.Hour), now.Add(60*24*time.Hour), "a.example.com", "b.example.com"),
		"a.example.com", "b.example.com")

	// 3) Renewing unexpired cert (must remain pullable!)
	renewID := "33333333333333333333333333333333"
	renewMeta := seedCertRecord(t, ctx, st, mgr, renewID, "renewing",
		makeTestCertWithExpiry(t, now.Add(-70*24*time.Hour), now.Add(20*24*time.Hour), "renewing.example.com"),
		"renewing.example.com")

	// 4) Expired cert (status="valid" in DB, but NotAfter in the past -> EffectiveStatus="expired", excluded from Pull!)
	expID := "44444444444444444444444444444444"
	seedCertRecord(t, ctx, st, mgr, expID, "valid",
		makeTestCertWithExpiry(t, now.Add(-92*24*time.Hour), now.Add(-2*24*time.Hour), "expired.example.com"),
		"expired.example.com")

	// 5) Two valid certs covering tie.example.com: insert later-expiring FIRST and earlier-expiring SECOND.
	tieLateID := "55555555555555555555555555555555"
	seedCertRecord(t, ctx, st, mgr, tieLateID, "valid",
		makeTestCertWithExpiry(t, now.Add(-time.Hour), now.Add(85*24*time.Hour), "tie.example.com", "tie-alt.example.com"),
		"tie.example.com", "tie-alt.example.com")

	tieEarlyID := "66666666666666666666666666666666"
	seedCertRecord(t, ctx, st, mgr, tieEarlyID, "valid",
		makeTestCertWithExpiry(t, now.Add(-time.Hour), now.Add(15*24*time.Hour), "tie.example.com"),
		"tie.example.com")

	srv := &web.Server{Store: st, Manager: mgr, InsecureCookie: true}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Verify GET /api/certificates marks expID as "expired" via certx.EffectiveStatus.
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": "correct-horse-battery"})
	loginReq, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.Header.Set("X-Requested-With", "certdns")
	loginRes, err := http.DefaultClient.Do(loginReq)
	if err != nil || loginRes.StatusCode != 200 {
		t.Fatalf("admin login failed: %v %v", loginRes, err)
	}
	var loginPayload struct {
		CSRF string `json:"csrf"`
	}
	_ = json.NewDecoder(loginRes.Body).Decode(&loginPayload)
	adminCookies := loginRes.Cookies()
	_ = loginRes.Body.Close()

	certListReq, _ := http.NewRequest("GET", ts.URL+"/api/certificates", nil)
	for _, ck := range adminCookies {
		certListReq.AddCookie(ck)
	}
	certListRes, err := http.DefaultClient.Do(certListReq)
	if err != nil || certListRes.StatusCode != 200 {
		t.Fatalf("listCertificates failed: %v %v", certListRes, err)
	}
	var certListPayload struct {
		Certificates []struct {
			ID       string `json:"id"`
			Status   string `json:"status"`
			DaysLeft *int   `json:"days_left"`
		} `json:"certificates"`
	}
	_ = json.NewDecoder(certListRes.Body).Decode(&certListPayload)
	_ = certListRes.Body.Close()
	foundExpired := false
	for _, c := range certListPayload.Certificates {
		if c.ID == expID {
			foundExpired = true
			if c.Status != "expired" || c.DaysLeft == nil || *c.DaysLeft >= 0 {
				t.Fatalf("expected expired status and negative days_left, got %+v", c)
			}
		}
	}
	if !foundExpired {
		t.Fatal("expected expID in listCertificates")
	}

	// Scoped tokens: subdomain-only, root-only, single-SAN, and global "*".
	_, subPlain, err := st.CreateAPIToken(ctx, "media-sub", []string{"media.example.org"})
	if err != nil {
		t.Fatal(err)
	}
	_, rootPlain, err := st.CreateAPIToken(ctx, "root-only", []string{"example.org"})
	if err != nil {
		t.Fatal(err)
	}
	_, singleSANPlain, err := st.CreateAPIToken(ctx, "single-san", []string{"a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	allTok, allPlain, err := st.CreateAPIToken(ctx, "all-nodes", []string{"*"})
	if err != nil {
		t.Fatal(err)
	}

	pull := func(token, path string, headers map[string]string) *http.Response {
		rq, _ := http.NewRequest("GET", ts.URL+path, nil)
		rq.Header.Set("Authorization", "Bearer "+token)
		for k, v := range headers {
			rq.Header.Set(k, v)
		}
		rs, err := http.DefaultClient.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}

	// Subdomain token MUST be denied (403) when trying to pull wildcard private key.
	if r := pull(subPlain, "/api/v1/pull/certificates/media.example.org?match_wildcard=1&file=privkey", nil); r.StatusCode != 403 {
		t.Fatalf("subdomain token must be forbidden (403) from pulling wildcard cert, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	// Root-only token MUST be denied (403) when cert also covers *.example.org.
	if r := pull(rootPlain, "/api/v1/pull/certificates/example.org?file=privkey", nil); r.StatusCode != 403 {
		t.Fatalf("root-only token must be forbidden (403) from pulling wildcard+root cert, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	// Single-SAN token MUST be denied (403) when cert covers [a.example.com, b.example.com].
	if r := pull(singleSANPlain, "/api/v1/pull/certificates/a.example.com?file=privkey", nil); r.StatusCode != 403 {
		t.Fatalf("single-SAN token must be forbidden (403) from pulling multi-SAN cert, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}

	// Pull list endpoint: includes valid & renewing unexpired certs, excludes expired cert!
	listRes := pull(allPlain, "/api/v1/pull/certificates", nil)
	if listRes.StatusCode != 200 {
		t.Fatalf("pullListCertificates failed: %d", listRes.StatusCode)
	}
	var pullList struct {
		Certificates []struct {
			ID string `json:"id"`
		} `json:"certificates"`
	}
	_ = json.NewDecoder(listRes.Body).Decode(&pullList)
	_ = listRes.Body.Close()
	seenPullIDs := map[string]bool{}
	for _, item := range pullList.Certificates {
		seenPullIDs[item.ID] = true
	}
	if !seenPullIDs[renewID] {
		t.Fatalf("expected renewing unexpired cert %s in pull list, got %v", renewID, seenPullIDs)
	}
	if seenPullIDs[expID] {
		t.Fatalf("expired cert %s must be excluded from pull list", expID)
	}

	// Renewing unexpired cert pulls cleanly with 200 OK.
	renRes := pull(allPlain, "/api/v1/pull/certificates/renewing.example.com", nil)
	if renRes.StatusCode != 200 {
		t.Fatalf("expected 200 pulling renewing unexpired cert, got %d", renRes.StatusCode)
	}
	_ = renRes.Body.Close()

	// Expired cert returns 404.
	expRes := pull(allPlain, "/api/v1/pull/certificates/expired.example.com", nil)
	if expRes.StatusCode != 404 {
		t.Fatalf("expected 404 pulling expired cert, got %d", expRes.StatusCode)
	}
	_ = expRes.Body.Close()

	// Tie-breaking selects latest NotAfter (tieLateID over tieEarlyID).
	tieRes := pull(allPlain, "/api/v1/pull/certificates/tie.example.com", nil)
	if tieRes.StatusCode != 200 {
		t.Fatalf("expected 200 pulling tie.example.com, got %d", tieRes.StatusCode)
	}
	var tieBody struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(tieRes.Body).Decode(&tieBody)
	_ = tieRes.Body.Close()
	if tieBody.ID != tieLateID {
		t.Fatalf("expected latest-expiring cert %s, got %s", tieLateID, tieBody.ID)
	}

	// Weak W/ and comma-separated multi-value If-None-Match return 304.
	multiETag := `"0000000000000000000000000000000000000000000000000000000000000000", W/"` + strings.ToUpper(renewMeta.SHA256) + `"`
	notModRes := pull(allPlain, "/api/v1/pull/certificates/renewing.example.com", map[string]string{
		"If-None-Match": multiETag,
	})
	if notModRes.StatusCode != 304 {
		t.Fatalf("expected 304 for weak multi-value If-None-Match, got %d", notModRes.StatusCode)
	}
	_ = notModRes.Body.Close()

	// Invalid ?file=invalid MUST return 400 BEFORE 304 and without setting ETag!
	badFileRes := pull(allPlain, "/api/v1/pull/certificates/renewing.example.com?file=invalid", map[string]string{
		"If-None-Match": `"` + renewMeta.SHA256 + `"`,
	})
	if badFileRes.StatusCode != 400 {
		t.Fatalf("expected 400 for invalid ?file= even when If-None-Match matches, got %d", badFileRes.StatusCode)
	}
	if gotETag := badFileRes.Header.Get("ETag"); gotETag != "" {
		t.Fatalf("expected no ETag on 400 invalid ?file=, got %q", gotETag)
	}
	_ = badFileRes.Body.Close()

	// ?file=privkey returns trailing-newline PEM and writes cert.pull audit log with file=privkey.
	pkRes := pull(allPlain, "/api/v1/pull/certificates/renewing.example.com?file=privkey", nil)
	if pkRes.StatusCode != 200 {
		t.Fatalf("expected 200 for ?file=privkey, got %d", pkRes.StatusCode)
	}
	pkBytes, _ := io.ReadAll(pkRes.Body)
	_ = pkRes.Body.Close()
	if len(pkBytes) == 0 || pkBytes[len(pkBytes)-1] != '\n' {
		t.Fatal("expected privkey response to end with newline")
	}

	logs, err := st.AuditLogs(ctx, store.AuditFilter{Action: "cert.pull", Keyword: "file=privkey", Limit: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(logs) == 0 || logs[0].Target != "renewing.example.com" || !strings.Contains(logs[0].Detail, "file=privkey") {
		t.Fatalf("expected cert.pull audit log with file=privkey, got %+v", logs)
	}

	// Token update validation: empty name rejected with 400; invalid ID rejected with 404.
	emptyNameBody, _ := json.Marshal(map[string]any{"name": "   "})
	updTokReq, _ := http.NewRequest("PUT", ts.URL+"/api/tokens/"+allTok.ID, bytes.NewReader(emptyNameBody))
	for _, ck := range adminCookies {
		updTokReq.AddCookie(ck)
	}
	updTokReq.Header.Set("Content-Type", "application/json")
	updTokReq.Header.Set("X-CSRF-Token", loginPayload.CSRF)
	updTokRes, err := http.DefaultClient.Do(updTokReq)
	if err != nil || updTokRes.StatusCode != 400 {
		t.Fatalf("expected 400 updating token with empty name, got %v %v", updTokRes, err)
	}
	_ = updTokRes.Body.Close()

	badIDReq, _ := http.NewRequest("DELETE", ts.URL+"/api/tokens/not-a-valid-hex-id", nil)
	for _, ck := range adminCookies {
		badIDReq.AddCookie(ck)
	}
	badIDReq.Header.Set("X-CSRF-Token", loginPayload.CSRF)
	badIDRes, err := http.DefaultClient.Do(badIDReq)
	if err != nil || badIDRes.StatusCode != 404 {
		t.Fatalf("expected 404 deleting invalid token ID, got %v %v", badIDRes, err)
	}
	_ = badIDRes.Body.Close()
}

func TestSecurityHardeningRateLimitWebhookCSPCookiesAndDecode(t *testing.T) {
	ctx := context.Background()
	st, tmp := openTestStore(t)
	seedAdminUser(t, ctx, st, "correct-horse-battery")
	mgr := issuer.New(st, tmp, filepath.Join(tmp, "tls"), "cert.example.org")

	// Use InsecureCookie: false to verify __Host-certdns_session and Strict-Transport-Security!
	srv := &web.Server{Store: st, Manager: mgr, InsecureCookie: false}
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	tryLogin := func(xff, password string) *http.Response {
		b, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
		rq, _ := http.NewRequest("POST", ts.URL+"/api/login", bytes.NewReader(b))
		rq.Header.Set("Content-Type", "application/json")
		rq.Header.Set("X-Requested-With", "certdns")
		if xff != "" {
			rq.Header.Set("X-Forwarded-For", xff)
		}
		rs, err := http.DefaultClient.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}

	// 1. Per-IP independent login rate limiting via X-Forwarded-For from loopback.
	for i := range 10 {
		r := tryLogin("203.0.113.77", "wrong-password")
		_ = r.Body.Close()
		if r.StatusCode != 401 {
			t.Fatalf("attempt %d: expected 401, got %d", i+1, r.StatusCode)
		}
	}
	blocked := tryLogin("203.0.113.77", "correct-horse-battery")
	_ = blocked.Body.Close()
	if blocked.StatusCode != 429 {
		t.Fatalf("11th attempt from scanner IP must return 429, got %d", blocked.StatusCode)
	}

	// Different IP (even via IPv4-mapped IPv6 XFF) is unaffected and receives __Host-certdns_session + HSTS!
	okRes := tryLogin("::ffff:198.51.100.88", "correct-horse-battery")
	if okRes.StatusCode != 200 {
		t.Fatalf("admin from separate IP must succeed (200), got %d", okRes.StatusCode)
	}
	if hsts := okRes.Header.Get("Strict-Transport-Security"); hsts != "max-age=31536000" {
		t.Fatalf("expected HSTS header when InsecureCookie=false, got %q", hsts)
	}
	csp := okRes.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'self'") || !strings.Contains(csp, "font-src 'self'") {
		t.Fatalf("unexpected CSP header: %q", csp)
	}
	var loginData struct {
		CSRF string `json:"csrf"`
	}
	_ = json.NewDecoder(okRes.Body).Decode(&loginData)
	cookies := okRes.Cookies()
	_ = okRes.Body.Close()

	foundHostCookie := false
	for _, ck := range cookies {
		if ck.Name == "__Host-certdns_session" && ck.Secure && ck.HttpOnly && ck.Path == "/" && ck.Domain == "" {
			foundHostCookie = true
		}
	}
	if !foundHostCookie {
		t.Fatalf("expected __Host-certdns_session cookie with Secure+Path=/+empty Domain, got %+v", cookies)
	}

	authedReq := func(method, path string, rawBody []byte, extraHeaders map[string]string) *http.Response {
		rq, _ := http.NewRequest(method, ts.URL+path, bytes.NewReader(rawBody))
		for _, ck := range cookies {
			rq.AddCookie(ck)
		}
		if rawBody != nil {
			rq.Header.Set("Content-Type", "application/json")
		}
		if method != "GET" && method != "HEAD" {
			rq.Header.Set("X-CSRF-Token", loginData.CSRF)
		}
		for k, v := range extraHeaders {
			rq.Header.Set(k, v)
		}
		rs, err := http.DefaultClient.Do(rq)
		if err != nil {
			t.Fatal(err)
		}
		return rs
	}

	// 2. Webhook SSRF blocking (127.0.0.1 and [::ffff:100.100.100.200]) & empty test URL rejection.
	for _, ssrfURL := range []string{
		"http://127.0.0.1:8080/hook",
		"http://[::ffff:100.100.100.200]/latest/meta-data/",
	} {
		body, _ := json.Marshal(map[string]string{"webhook_url": ssrfURL})
		r := authedReq("PUT", "/api/settings/webhook", body, nil)
		_ = r.Body.Close()
		if r.StatusCode != 400 {
			t.Fatalf("expected 400 blocking SSRF webhook %s, got %d", ssrfURL, r.StatusCode)
		}
	}

	validHook := "https://oapi.dingtalk.com/robot/send?access_token=supersecrettoken12345"
	hookBody, _ := json.Marshal(map[string]string{"webhook_url": validHook})
	if r := authedReq("PUT", "/api/settings/webhook", hookBody, nil); r.StatusCode != 200 {
		t.Fatalf("expected 200 saving public webhook URL, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	// Audit log must mask the webhook token.
	wLogs, err := st.AuditLogs(ctx, store.AuditFilter{Action: "webhook.update", Limit: 5})
	if err != nil || len(wLogs) == 0 || strings.Contains(wLogs[0].Target, "supersecrettoken12345") || !strings.Contains(wLogs[0].Target, "••••") {
		t.Fatalf("expected masked webhook URL in audit log, got %+v (err=%v)", wLogs, err)
	}

	// Explicit empty webhook_url: "" on /api/settings/webhook/test MUST return 400 instead of falling back to saved URL.
	emptyTestBody, _ := json.Marshal(map[string]string{"webhook_url": ""})
	if r := authedReq("POST", "/api/settings/webhook/test", emptyTestBody, nil); r.StatusCode != 400 {
		t.Fatalf("expected 400 testing explicit empty webhook_url, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}

	// 3. Sec-Fetch-Site cross-site blocked even on GET routes.
	if r := authedReq("GET", "/api/settings", nil, map[string]string{"Sec-Fetch-Site": "cross-site"}); r.StatusCode != 403 {
		t.Fatalf("expected 403 on cross-site Sec-Fetch-Site GET, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}

	// 4. Static /assets/ isolation & removed legacy routes.
	for _, p := range []string{"/assets/", "/assets/index.html"} {
		r, err := http.Get(ts.URL + p)
		if err != nil {
			t.Fatal(err)
		}
		_ = r.Body.Close()
		if r.StatusCode != 404 {
			t.Fatalf("expected 404 for %s, got %d", p, r.StatusCode)
		}
	}
	cssRes, err := http.Get(ts.URL + "/assets/style.css")
	if err != nil {
		t.Fatal(err)
	}
	_ = cssRes.Body.Close()
	if cssRes.StatusCode != 200 {
		t.Fatalf("expected 200 for /assets/style.css, got %d", cssRes.StatusCode)
	}

	if r := authedReq("POST", "/api/settings/test", []byte(`{}`), nil); r.StatusCode != 404 {
		t.Fatalf("expected 404 for removed POST /api/settings/test, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	if r := authedReq("PUT", "/api/settings", []byte(`{}`), nil); r.StatusCode != 405 && r.StatusCode != 404 {
		t.Fatalf("expected 405/404 for removed PUT /api/settings, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}

	// 5. decode rejects trailing JSON garbage (400) and >256KB payload (413).
	if r := authedReq("PUT", "/api/settings/webhook", []byte(`{"webhook_url":""}{"extra":1}`), nil); r.StatusCode != 400 {
		t.Fatalf("expected 400 on trailing JSON object, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
	huge := append([]byte(`{"webhook_url":"https://example.com/`), bytes.Repeat([]byte("a"), 260<<10)...)
	huge = append(huge, []byte(`"}`)...)
	if r := authedReq("PUT", "/api/settings/webhook", huge, nil); r.StatusCode != 413 {
		t.Fatalf("expected 413 on >256KB body, got %d", r.StatusCode)
	} else {
		_ = r.Body.Close()
	}
}
