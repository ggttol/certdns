package alidns

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
)

func TestPercentEncoding(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{in: " ", want: "%20"},
		{in: "+", want: "%2B"},
		{in: "*", want: "%2A"},
		{in: "~", want: "~"},
		{in: "a+b *c~d/e=f", want: "a%2Bb%20%2Ac~d%2Fe%3Df"},
		{in: "_acme-challenge.example.com", want: "_acme-challenge.example.com"},
	}
	for _, tc := range cases {
		if got := percent(tc.in); got != tc.want {
			t.Errorf("percent(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSignDeterminismAndRPCVerification(t *testing.T) {
	t.Parallel()

	cnClient := New(Credentials{
		KeyID:    "testid",
		Secret:   "testsecret",
		Edition:  EditionCN,
		Endpoint: "http://127.0.0.1:9999/",
	})
	if cnClient.Endpoint != DefaultCNEndpoint {
		t.Fatalf("EditionCN Endpoint = %q, want %q", cnClient.Endpoint, DefaultCNEndpoint)
	}
	if cnClient.RegionID != DefaultCNRegion || cnClient.Lang != "zh" {
		t.Fatalf("unexpected CN defaults: region=%q lang=%q", cnClient.RegionID, cnClient.Lang)
	}

	intlClient := New(Credentials{
		KeyID:   "testid",
		Secret:  "testsecret",
		Edition: EditionIntl,
	})
	if intlClient.Endpoint != DefaultIntlEndpoint || intlClient.RegionID != DefaultIntlRegion || intlClient.Lang != "en" {
		t.Fatalf("unexpected Intl defaults: endpoint=%q region=%q lang=%q", intlClient.Endpoint, intlClient.RegionID, intlClient.Lang)
	}

	fixedArgs := map[string]string{
		"SignatureNonce": "nonce-123",
		"Timestamp":      "2026-01-02T03:04:05Z",
		"DomainName":     "example.com",
		"RR":             "*",
		"Type":           "TXT",
		"Value":          "v=spf1 +mx ~all",
	}
	v1 := cnClient.sign("AddDomainRecord", fixedArgs)
	v2 := cnClient.sign("AddDomainRecord", fixedArgs)

	const wantSig = "2/eklsAk9xWBmZAuZ8z7bZT0DSA="
	if got := v1.Get("Signature"); got != wantSig {
		t.Fatalf("Signature = %q, want %q", got, wantSig)
	}
	if v1.Encode() != v2.Encode() {
		t.Fatalf("sign is not deterministic: %q != %q", v1.Encode(), v2.Encode())
	}

	spaceArgs := map[string]string{
		"SignatureNonce": "nonce-123",
		"Timestamp":      "2026-01-02T03:04:05Z",
		"DomainName":     "example.com",
		"RR":             "*",
		"Type":           "TXT",
		"Value":          "v=spf1  mx ~all",
	}
	if cnClient.sign("AddDomainRecord", spaceArgs).Get("Signature") == wantSig {
		t.Fatal("expected '+' and ' ' to produce distinct signatures")
	}

	const secret = "rpc-secret-key"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
		}
		vals, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Errorf("ParseQuery: %v", err)
		}
		gotSig := vals.Get("Signature")
		vals.Del("Signature")

		keys := make([]string, 0, len(vals))
		for k := range vals {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = percent(k) + "=" + percent(vals.Get(k))
		}
		mac := hmac.New(sha1.New, []byte(secret+"&"))
		mac.Write([]byte("POST&%2F&" + percent(strings.Join(parts, "&"))))
		expectedSig := base64.StdEncoding.EncodeToString(mac.Sum(nil))
		if gotSig != expectedSig {
			http.Error(w, `{"Code":"SignatureDoesNotMatch"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"RecordId":"rec-signed-1"}`))
	}))
	defer srv.Close()

	c := New(Credentials{
		KeyID:    "LTAI5tSignedKey",
		Secret:   secret,
		Edition:  EditionCustom,
		Endpoint: srv.URL,
	})
	id, err := c.AddRecord(context.Background(), "example.com", RecordInput{
		RR:    "*",
		Type:  "TXT",
		Value: "a+b *c ~d",
		TTL:   600,
	})
	if err != nil {
		t.Fatalf("AddRecord failed signature check: %v", err)
	}
	if id != "rec-signed-1" {
		t.Fatalf("RecordId = %q, want rec-signed-1", id)
	}
}

func TestAllRecordsPagination(t *testing.T) {
	t.Parallel()

	const totalRecords = 1005
	var (
		mu             sync.Mutex
		pagesRequested []int
	)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("ParseForm: %v", err)
		}
		if got := r.Form.Get("Action"); got != "DescribeDomainRecords" {
			t.Errorf("Action = %q, want DescribeDomainRecords", got)
		}
		if got := r.Form.Get("DomainName"); got != "example.com" {
			t.Errorf("DomainName = %q, want example.com", got)
		}
		if got := r.Form.Get("RRKeyWord"); got != "_acme-challenge" {
			t.Errorf("RRKeyWord = %q, want _acme-challenge", got)
		}
		if got := r.Form.Get("TypeKeyWord"); got != "TXT" {
			t.Errorf("TypeKeyWord = %q, want TXT", got)
		}
		if got := r.Form.Get("KeyWord"); got != "tok" {
			t.Errorf("KeyWord = %q, want tok", got)
		}
		page, err := strconv.Atoi(r.Form.Get("PageNumber"))
		if err != nil {
			t.Errorf("invalid PageNumber: %v", err)
		}
		pageSize, err := strconv.Atoi(r.Form.Get("PageSize"))
		if err != nil || pageSize != 500 {
			t.Errorf("PageSize = %q, want 500", r.Form.Get("PageSize"))
		}
		mu.Lock()
		pagesRequested = append(pagesRequested, page)
		mu.Unlock()

		start := (page-1)*pageSize + 1
		end := page * pageSize
		if end > totalRecords {
			end = totalRecords
		}
		var batch []Record
		for i := start; i <= end; i++ {
			batch = append(batch, Record{
				RecordID:   fmt.Sprintf("rec-%d", i),
				DomainName: "example.com",
				RR:         "_acme-challenge",
				Type:       "TXT",
				Value:      fmt.Sprintf("tok-%d", i),
				TTL:        600,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"TotalCount": totalRecords,
			"DomainRecords": map[string]any{
				"Record": batch,
			},
		})
	}))
	defer srv.Close()

	c := New(Credentials{
		KeyID:    "LTAI5tPageKey",
		Secret:   "page-secret",
		Edition:  EditionCustom,
		Endpoint: srv.URL,
	})
	got, err := c.AllRecords(context.Background(), RecordQuery{
		Zone:    "example.com",
		RRKey:   "_acme-challenge",
		TypeKey: "TXT",
		Keyword: "tok",
	})
	if err != nil {
		t.Fatalf("AllRecords error: %v", err)
	}
	mu.Lock()
	gotPages := append([]int(nil), pagesRequested...)
	mu.Unlock()
	if len(gotPages) != 3 || gotPages[0] != 1 || gotPages[1] != 2 || gotPages[2] != 3 {
		t.Fatalf("pagesRequested = %v, want [1 2 3]", gotPages)
	}
	if len(got) != totalRecords {
		t.Fatalf("len(got) = %d, want %d", len(got), totalRecords)
	}
	if got[0].RecordID != "rec-1" || got[totalRecords-1].RecordID != "rec-1005" {
		t.Fatalf("unexpected boundary records: first=%q last=%q", got[0].RecordID, got[totalRecords-1].RecordID)
	}
}

func TestUpdateRecordRemark(t *testing.T) {
	t.Parallel()

	var (
		mu       sync.Mutex
		captured []url.Values
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("ReadAll: %v", err)
		}
		vals, err := url.ParseQuery(string(raw))
		if err != nil {
			t.Errorf("ParseQuery: %v", err)
		}
		mu.Lock()
		captured = append(captured, vals)
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"RequestId":"req-1"}`))
	}))
	defer srv.Close()

	c := New(Credentials{
		KeyID:    "LTAI5tRemarkKey",
		Secret:   "remark-secret",
		Edition:  EditionCustom,
		Endpoint: srv.URL,
	})

	if err := c.UpdateRecordRemark(context.Background(), "rec-100", "production ingress"); err != nil {
		t.Fatalf("UpdateRecordRemark non-empty: %v", err)
	}
	if err := c.UpdateRecordRemark(context.Background(), "rec-100", ""); err != nil {
		t.Fatalf("UpdateRecordRemark empty: %v", err)
	}

	mu.Lock()
	reqs := append([]url.Values(nil), captured...)
	mu.Unlock()
	if len(reqs) != 2 {
		t.Fatalf("captured %d requests, want 2", len(reqs))
	}
	if reqs[0].Get("Action") != "UpdateDomainRecordRemark" || reqs[0].Get("RecordId") != "rec-100" {
		t.Fatalf("unexpected first request params: %v", reqs[0])
	}
	if !reqs[0].Has("Remark") || reqs[0].Get("Remark") != "production ingress" {
		t.Fatalf("Remark in first request = %q (present=%v), want %q", reqs[0].Get("Remark"), reqs[0].Has("Remark"), "production ingress")
	}
	if reqs[1].Get("Action") != "UpdateDomainRecordRemark" || reqs[1].Get("RecordId") != "rec-100" {
		t.Fatalf("unexpected second request params: %v", reqs[1])
	}
	if reqs[1].Has("Remark") {
		t.Fatalf("expected Remark parameter to be omitted when clearing remark, got %q", reqs[1].Get("Remark"))
	}
}

func TestIsRecordNotFound(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: false},
		{name: "plain error", err: errors.New("eof"), want: false},
		{name: "empty code", err: &Error{Message: "网络连接失败"}, want: false},
		{name: "DomainRecordNotBelongToUser", err: &Error{Code: "DomainRecordNotBelongToUser"}, want: true},
		{name: "DomainNotFound", err: &Error{Code: "DomainNotFound"}, want: true},
		{name: "InvalidRR.NoExist", err: &Error{Code: "InvalidRR.NoExist"}, want: true},
		{name: "DomainRecordNotExist", err: &Error{Code: "DomainRecordNotExist"}, want: true},
		{name: "RecordId.NotFound", err: &Error{Code: "RecordId.NotFound"}, want: true},
		{name: "wrapped not found", err: fmt.Errorf("wrap: %w", &Error{Code: "InvalidRR.NoExist"}), want: true},
		{name: "InvalidAccessKeyId.NotFound", err: &Error{Code: "InvalidAccessKeyId.NotFound"}, want: false},
		{name: "SignatureDoesNotMatch", err: &Error{Code: "SignatureDoesNotMatch"}, want: false},
		{name: "DomainRecordDuplicate", err: &Error{Code: "DomainRecordDuplicate"}, want: false},
	}

	for _, tc := range cases {
		if got := IsRecordNotFound(tc.err); got != tc.want {
			t.Errorf("%s: IsRecordNotFound(%v) = %v, want %v", tc.name, tc.err, got, tc.want)
		}
	}
}

func TestHint(t *testing.T) {
	t.Parallel()

	cases := []struct {
		err  error
		want string
	}{
		{
			err:  &Error{Code: "InvalidRR.NoExist"},
			want: "解析记录或域名不存在 (InvalidRR.NoExist)",
		},
		{
			err:  &Error{Code: "DomainRecordNotBelongToUser"},
			want: "解析记录或域名不存在 (DomainRecordNotBelongToUser)",
		},
		{
			err:  &Error{Code: "DomainNotFound"},
			want: "解析记录或域名不存在 (DomainNotFound)",
		},
		{
			err:  &Error{Code: "DomainRecordNotExist"},
			want: "解析记录或域名不存在 (DomainRecordNotExist)",
		},
		{
			err:  &Error{Code: "RecordId.NotFound"},
			want: "解析记录或域名不存在 (RecordId.NotFound)",
		},
		{
			err:  &Error{Code: "InvalidAccessKeyId.NotFound"},
			want: "AccessKey 无效、版本不匹配或 RAM 权限不足 (InvalidAccessKeyId.NotFound)",
		},
		{
			err:  &Error{Code: "SignatureDoesNotMatch"},
			want: "AccessKey 无效、版本不匹配或 RAM 权限不足 (SignatureDoesNotMatch)",
		},
		{
			err:  &Error{Code: "DomainRecordDuplicate"},
			want: "记录或域名已存在 (DomainRecordDuplicate)",
		},
		{
			err:  &Error{Code: "DomainAlreadyExists"},
			want: "记录或域名已存在 (DomainAlreadyExists)",
		},
		{
			err:  &Error{Code: "MissingCredentials"},
			want: "请先在“阿里云账户”中配置有效的 AccessKey",
		},
		{
			err:  &Error{Code: "Throttling.User"},
			want: "阿里云接口限流，请稍后重试 (Throttling.User)",
		},
		{
			err:  &Error{Code: "InvalidTTL"},
			want: "TTL 不被当前解析版本支持，免费版最小 600 秒 (InvalidTTL)",
		},
		{
			err:  &Error{Code: "RecordConflict"},
			want: "与已有记录冲突，例如 CNAME 不能与其他记录共存 (RecordConflict)",
		},
		{
			err:  errors.New("timeout"),
			want: "阿里云 DNS 请求失败，请检查网络后重试",
		},
	}

	for _, tc := range cases {
		if got := Hint(tc.err); got != tc.want {
			t.Errorf("Hint(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
}
