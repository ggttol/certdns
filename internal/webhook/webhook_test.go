package webhook

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync"
	"testing"
)

func TestValidateURLAndTarget(t *testing.T) {
	t.Parallel()

	u, err := ValidateURL("   ")
	if err != nil || u != "" {
		t.Fatalf("empty ValidateURL = (%q, %v), want (\"\", nil)", u, err)
	}

	u, err = ValidateURL("  https://oapi.dingtalk.com/robot/send?access_token=abc  ")
	if err != nil || u != "https://oapi.dingtalk.com/robot/send?access_token=abc" {
		t.Fatalf("trimmed ValidateURL = (%q, %v)", u, err)
	}

	invalidURLs := []string{
		"ftp://example.com/hook",
		"javascript:alert(1)",
		"file:///etc/passwd",
		"example.com/hook",
		"http:///missing-host",
		"https://:8443/missing-host",
		"https://user:pass@example.com/hook",
		"https://token@example.com/hook",
		"https://@example.com/hook",
	}
	for _, raw := range invalidURLs {
		if _, err := ValidateURL(raw); err == nil {
			t.Errorf("ValidateURL(%q) succeeded, want error", raw)
		}
		if _, err := ValidateTarget(raw, true); err == nil {
			t.Errorf("ValidateTarget(%q, true) succeeded, want error", raw)
		}
	}

	publicTargets := []string{
		"https://oapi.dingtalk.com/robot/send?access_token=xyz",
		"http://8.8.8.8:8080/hook",
		"https://[2606:4700:4700::1111]/hook",
	}
	for _, raw := range publicTargets {
		if _, err := ValidateTarget(raw, false); err != nil {
			t.Errorf("ValidateTarget(%q, false) unexpected error: %v", raw, err)
		}
	}

	privateOrMetadataTargets := []string{
		"http://127.0.0.1:8080/hook",
		"http://127.0.0.1./hook",
		"http://10.0.0.1/hook",
		"http://172.16.0.1/hook",
		"http://192.168.1.1/hook",
		"http://169.254.169.254/latest/meta-data/",
		"http://100.100.100.200/latest/meta-data/",
		"http://[::ffff:100.100.100.200]/latest/meta-data/",
		"http://[::ffff:127.0.0.1]:8080/hook",
		"http://[::1]:8080/hook",
		"http://[64:ff9b::100.100.100.200]/hook",
		"http://[fc00::1]/hook",
		"http://[fe80::1]/hook",
	}
	for _, raw := range privateOrMetadataTargets {
		if _, err := ValidateTarget(raw, false); err == nil {
			t.Errorf("ValidateTarget(%q, false) succeeded, want SSRF rejection", raw)
		}
		if got, err := ValidateTarget(raw, true); err != nil || got != raw {
			t.Errorf("ValidateTarget(%q, true) = (%q, %v), want (%q, nil)", raw, got, err, raw)
		}
	}
}

func TestIsBlockedAddr(t *testing.T) {
	t.Parallel()

	if !IsBlockedAddr(netip.Addr{}) {
		t.Fatal("zero netip.Addr must be blocked")
	}

	blocked := []string{
		"0.0.0.0",
		"10.1.2.3",
		"100.64.0.1",
		"100.100.100.200",
		"127.0.0.1",
		"169.254.169.254",
		"172.16.0.1",
		"172.31.255.254",
		"192.0.0.1",
		"192.0.2.1",
		"192.168.1.1",
		"198.18.0.1",
		"198.51.100.1",
		"203.0.113.1",
		"224.0.0.1",
		"240.0.0.1",
		"255.255.255.255",
		"::",
		"::1",
		"::ffff:127.0.0.1",
		"::ffff:100.100.100.200",
		"64:ff9b::1",
		"64:ff9b:1::1",
		"100::1",
		"2001:db8::1",
		"2002::1",
		"fc00::1",
		"fd12:3456::1",
		"fe80::1",
		"ff02::1",
		"2001:4860:4860::8888%eth0",
	}
	for _, s := range blocked {
		addr := netip.MustParseAddr(s)
		if !IsBlockedAddr(addr) {
			t.Errorf("IsBlockedAddr(%q) = false, want true", s)
		}
	}

	allowed := []string{
		"1.1.1.1",
		"8.8.8.8",
		"100.63.255.254",
		"100.128.0.1",
		"172.15.255.254",
		"172.32.0.1",
		"223.5.5.5",
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
	}
	for _, s := range allowed {
		addr := netip.MustParseAddr(s)
		if IsBlockedAddr(addr) {
			t.Errorf("IsBlockedAddr(%q) = true, want false", s)
		}
	}
}

func TestMaskURL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   string
		want string
	}{
		{
			in:   "   ",
			want: "",
		},
		{
			// DingTalk query parameters without percent-encoding ••••
			in:   "https://oapi.dingtalk.com/robot/send?access_token=abcdef1234567890&sign=xyz987",
			want: "https://oapi.dingtalk.com/robot/send?access_token=••••&sign=••••",
		},
		{
			// WeCom query key
			in:   "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=693axxx6-7aoc-4bc4-97a0-0ec2sifa5aaa",
			want: "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=••••",
		},
		{
			// Telegram middle segment (/bot<token>/sendMessage where sendMessage is 11 chars)
			in:   "https://api.telegram.org/bot123456:ABCDEF/sendMessage",
			want: "https://api.telegram.org/bot1••••/sendMessage",
		},
		{
			// Telegram middle segment + query param
			in:   "https://api.telegram.org/bot123456:ABCDEF/sendMessage?chat_id=-100123456",
			want: "https://api.telegram.org/bot1••••/sendMessage?chat_id=••••",
		},
		{
			// Feishu trailing token
			in:   "https://open.feishu.cn/open-apis/bot/v2/hook/01234567-89ab-cdef-0123-456789abcdef",
			want: "https://open.feishu.cn/open-apis/bot/v2/hook/0123••••",
		},
		{
			// Slack trailing token
			in:   "https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXXXXXX",
			want: "https://hooks.slack.com/services/T00000000/B00000000/XXXX••••",
		},
		{
			// Short colon segments (<= 4 chars must not panic on slice bounds)
			in:   "https://example.com/a:b/hook",
			want: "https://example.com/••••/hook",
		},
		{
			in:   "https://example.com/ab:c/hook",
			want: "https://example.com/••••/hook",
		},
		{
			in:   "https://example.com/abc:d/hook",
			want: "https://example.com/abc:••••/hook",
		},
		{
			// Embedded userinfo
			in:   "https://admin:secretpass@example.com/webhook?token=abc",
			want: "https://••••@example.com/webhook?token=••••",
		},
	}

	for _, tc := range cases {
		if got := MaskURL(tc.in); got != tc.want {
			t.Errorf("MaskURL(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestSenderSendSSRFAndDelivery(t *testing.T) {
	t.Parallel()

	var (
		mu              sync.Mutex
		hits            int
		lastContentType string
		lastRawBody     []byte
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		hits++
		lastContentType = r.Header.Get("Content-Type")
		lastRawBody = body
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/fail", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "upstream failure", http.StatusBadGateway)
	})
	// 3 hops: /r3/0 -> /r3/1 -> /r3/2 -> /ok (allowed, == 3 redirects)
	mux.HandleFunc("/r3/0", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/r3/1", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/r3/1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/r3/2", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/r3/2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
	})
	// 4 hops: /r4/0 -> /r4/1 -> /r4/2 -> /r4/3 -> /ok (blocked, > 3 redirects)
	mux.HandleFunc("/r4/0", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/r4/1", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/r4/1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/r4/2", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/r4/2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/r4/3", http.StatusTemporaryRedirect)
	})
	mux.HandleFunc("/r4/3", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ok", http.StatusTemporaryRedirect)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	_, port, err := net.SplitHostPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", srv.Listener.Addr().String(), err)
	}

	v4Base := "http://127.0.0.1:" + port
	v4InV6Base := "http://[::ffff:127.0.0.1]:" + port

	ctx := context.Background()
	sender := NewSender("cert.example.org")

	// 1. Default AllowPrivate=false must reject IPv4 loopback, IPv4-in-IPv6 loopback, and empty URL.
	if err := sender.Send(ctx, "", "标题", "内容"); err == nil {
		t.Fatal("Send empty URL succeeded, want error")
	}
	if err := sender.Send(ctx, v4Base+"/ok", "标题", "内容"); err == nil {
		t.Fatal("Send to 127.0.0.1 succeeded when AllowPrivate=false, want SSRF error")
	}
	if err := sender.Send(ctx, v4InV6Base+"/ok", "标题", "内容"); err == nil {
		t.Fatal("Send to [::ffff:127.0.0.1] succeeded when AllowPrivate=false, want SSRF error")
	}
	if _, err := sender.dialContext(ctx, "tcp", "[::ffff:100.100.100.200]:80"); err == nil {
		t.Fatal("dialContext to [::ffff:100.100.100.200] succeeded when AllowPrivate=false")
	}

	mu.Lock()
	if hits != 0 {
		t.Fatalf("server received %d hits while AllowPrivate=false, want 0", hits)
	}
	mu.Unlock()

	// 2. Mutate AllowPrivate=true on the SAME Sender instance; must take immediate effect.
	sender.AllowPrivate = true

	if err := sender.Send(ctx, v4Base+"/ok", "证书续期成功", "域名: cert.example.org"); err != nil {
		t.Fatalf("Send to 127.0.0.1 with AllowPrivate=true failed: %v", err)
	}

	mu.Lock()
	gotHits := hits
	gotCT := lastContentType
	rawCopy := append([]byte(nil), lastRawBody...)
	mu.Unlock()

	if gotHits != 1 {
		t.Fatalf("hits = %d, want 1", gotHits)
	}
	if gotCT != "application/json" {
		t.Fatalf("Content-Type = %q, want application/json", gotCT)
	}

	var decoded struct {
		MsgType       string `json:"msgtype"`
		FeishuMsgType string `json:"msg_type"`
		Title         string `json:"title"`
		Text          struct {
			Content string `json:"content"`
		} `json:"text"`
		Content struct {
			Text string `json:"text"`
		} `json:"content"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(rawCopy, &decoded); err != nil {
		t.Fatalf("json.Unmarshal payload: %v", err)
	}
	if decoded.MsgType != "text" || decoded.FeishuMsgType != "text" {
		t.Fatalf("unexpected msg types: msgtype=%q msg_type=%q", decoded.MsgType, decoded.FeishuMsgType)
	}
	if decoded.Title != "证书续期成功" {
		t.Fatalf("title = %q, want 证书续期成功", decoded.Title)
	}
	wantParts := []string{
		"【CertDNS 证书续期成功】",
		"主机: cert.example.org",
		"域名: cert.example.org",
		"时间: ",
	}
	for _, p := range wantParts {
		if !strings.Contains(decoded.Message, p) {
			t.Errorf("message %q missing %q", decoded.Message, p)
		}
	}
	if decoded.Text.Content != decoded.Message || decoded.Content.Text != decoded.Message {
		t.Fatalf("payload text fields mismatch: text.content=%q content.text=%q message=%q",
			decoded.Text.Content, decoded.Content.Text, decoded.Message)
	}

	// 3. IPv4-in-IPv6 unmapped delivery on the same Sender when AllowPrivate=true.
	if err := sender.Send(ctx, v4InV6Base+"/ok", "双栈测试", "内容"); err != nil {
		t.Fatalf("Send to [::ffff:127.0.0.1] with AllowPrivate=true failed: %v", err)
	}

	// 4. HTTP >= 400 returns error.
	if err := sender.Send(ctx, v4Base+"/fail", "错误码测试", "内容"); err == nil || !strings.Contains(err.Error(), "502") {
		t.Fatalf("Send to /fail = %v, want HTTP 502 error", err)
	}

	// 5. Up to 3 redirects succeed; > 3 redirects fail.
	if err := sender.Send(ctx, v4Base+"/r3/0", "重定向测试", "三跳允许"); err != nil {
		t.Fatalf("Send with 3 redirects failed: %v", err)
	}
	if err := sender.Send(ctx, v4Base+"/r4/0", "重定向测试", "四跳拦截"); err == nil {
		t.Fatal("Send with 4 redirects succeeded, want redirect limit error")
	}

	// 6. Toggling AllowPrivate=false back on the same Sender immediately blocks again.
	sender.AllowPrivate = false
	if err := sender.Send(ctx, v4Base+"/ok", "再次拦截", "内容"); err == nil {
		t.Fatal("Send succeeded after resetting AllowPrivate=false, want SSRF error")
	}
}
