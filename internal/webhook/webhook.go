// Package webhook validates, masks, and delivers outbound webhook notifications
// with SSRF protection against loopback, private networks, and cloud metadata endpoints.
package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

const (
	defaultTimeout = 10 * time.Second
	maxRedirects   = 3
)

var blockedPrefixes = []netip.Prefix{
	// IPv4 special-purpose, private, and cloud metadata ranges
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"), // Carrier-grade NAT & Alibaba Cloud IMDS (100.100.100.200)
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),

	// IPv6 special-purpose, loopback, link-local, ULA, NAT64, and 6to4 ranges
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

// ValidateURL validates the basic structure and scheme of a webhook URL.
// An empty or whitespace-only string returns ("", nil).
func ValidateURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("Webhook 地址格式无效: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", errors.New("Webhook 地址需以 https:// 或 http:// 开头")
	}
	if u.Hostname() == "" {
		return "", errors.New("Webhook 地址缺少有效主机名")
	}
	if u.User != nil {
		return "", errors.New("Webhook 地址不允许包含账号或密码")
	}
	return s, nil
}

// IsBlockedAddr reports whether addr is invalid, non-global-unicast, or falls
// within any reserved, loopback, private, link-local, or cloud metadata prefix.
// IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) are unmapped first.
func IsBlockedAddr(addr netip.Addr) bool {
	hasZone := addr.Zone() != ""
	addr = addr.Unmap()
	if !addr.IsValid() || hasZone || !addr.IsGlobalUnicast() {
		return true
	}
	for _, p := range blockedPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// ValidateTarget validates raw via ValidateURL and, when allowPrivate is false,
// rejects literal private/reserved/metadata IP hosts synchronously.
func ValidateTarget(raw string, allowPrivate bool) (string, error) {
	s, err := ValidateURL(raw)
	if err != nil || s == "" || allowPrivate {
		return s, err
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", fmt.Errorf("Webhook 地址格式无效: %w", err)
	}
	if addr, ok := parseHostLiteral(u.Hostname()); ok && IsBlockedAddr(addr) {
		return "", fmt.Errorf("禁止使用内网、回环或保留地址作为 Webhook 目标 (%s)", addr.Unmap())
	}
	return s, nil
}

func parseHostLiteral(host string) (netip.Addr, bool) {
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr, true
	}
	trimmed := strings.TrimSuffix(host, ".")
	if trimmed != host {
		if addr, err := netip.ParseAddr(trimmed); err == nil {
			return addr, true
		}
	}
	return netip.Addr{}, false
}

// MaskURL redacts embedded credentials, query parameter values, and token-like
// path segments without percent-encoding the mask characters.
func MaskURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil {
		return "••••"
	}
	if u.Opaque != "" {
		if u.Scheme != "" {
			return u.Scheme + ":••••"
		}
		return "••••"
	}

	var b strings.Builder
	b.Grow(len(s))
	if u.Scheme != "" {
		b.WriteString(u.Scheme)
		b.WriteString("://")
	}
	if u.User != nil {
		b.WriteString("••••@")
	}
	b.WriteString(u.Host)

	if u.Path != "" {
		if u.Host != "" && !strings.HasPrefix(u.Path, "/") {
			b.WriteByte('/')
		}
		segs := strings.Split(u.Path, "/")
		for i, seg := range segs {
			if i > 0 {
				b.WriteByte('/')
			}
			b.WriteString(maskPathSegment(seg))
		}
	}

	if u.RawQuery != "" {
		parts := strings.Split(u.RawQuery, "&")
		wrote := false
		for _, part := range parts {
			if part == "" {
				continue
			}
			if !wrote {
				b.WriteByte('?')
				wrote = true
			} else {
				b.WriteByte('&')
			}
			if idx := strings.IndexByte(part, '='); idx >= 0 {
				b.WriteString(part[:idx])
				b.WriteString("=••••")
			} else {
				b.WriteString("••••")
			}
		}
	}

	if u.Fragment != "" {
		b.WriteString("#••••")
	}

	return b.String()
}

func maskPathSegment(seg string) string {
	if len(seg) < 12 && !strings.Contains(seg, ":") {
		return seg
	}
	if strings.Contains(seg, ":") && len(seg) <= 4 {
		return "••••"
	}
	r := []rune(seg)
	if len(r) <= 4 {
		return "••••"
	}
	return string(r[:4]) + "••••"
}

// Sender dispatches webhook notifications over an SSRF-hardened HTTP client.
type Sender struct {
	Hostname     string
	AllowPrivate bool
	Timeout      time.Duration
}

// NewSender creates a webhook Sender with a default 10s timeout and private IP blocking enabled.
func NewSender(hostname string) *Sender {
	return &Sender{
		Hostname: hostname,
		Timeout:  defaultTimeout,
	}
}

func (s *Sender) timeout() time.Duration {
	if s != nil && s.Timeout > 0 {
		return s.Timeout
	}
	return defaultTimeout
}

func (s *Sender) allowPrivate() bool {
	return s != nil && s.AllowPrivate
}

func (s *Sender) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	host = strings.TrimSuffix(host, ".")
	if host == "" || port == "" {
		return nil, fmt.Errorf("Webhook 目标地址无效: %s", address)
	}

	allowPrivate := s.allowPrivate()
	var targets []netip.Addr

	if literal, err := netip.ParseAddr(host); err == nil {
		hasZone := literal.Zone() != ""
		zone := literal.Zone()
		addr := literal.Unmap()
		if !allowPrivate && (hasZone || IsBlockedAddr(addr)) {
			return nil, fmt.Errorf("禁止连接内网、回环或保留地址 (%s)", addr)
		}
		if hasZone && addr.Is6() {
			addr = addr.WithZone(zone)
		}
		targets = []netip.Addr{addr}
	} else {
		ipAddrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
		if err != nil {
			return nil, err
		}
		if len(ipAddrs) == 0 {
			return nil, fmt.Errorf("域名 %s 未解析到任何 IP 地址", host)
		}
		targets = make([]netip.Addr, 0, len(ipAddrs))
		for _, ipa := range ipAddrs {
			rawAddr, ok := netip.AddrFromSlice(ipa.IP)
			if !ok {
				return nil, fmt.Errorf("域名 %s 解析到无效 IP", host)
			}
			addr := rawAddr.Unmap()
			if !allowPrivate && (ipa.Zone != "" || IsBlockedAddr(addr)) {
				return nil, fmt.Errorf("域名 %s 解析到受限内网或保留地址 (%s)", host, addr)
			}
			if ipa.Zone != "" && addr.Is6() {
				addr = addr.WithZone(ipa.Zone)
			}
			targets = append(targets, addr)
		}
	}

	dialer := &net.Dialer{
		Timeout: s.timeout(),
	}
	var lastErr error
	for _, addr := range targets {
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(addr.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, lastErr
}

type textContent struct {
	Content string `json:"content"`
}

type feishuContent struct {
	Text string `json:"text"`
}

type universalPayload struct {
	MsgType       string        `json:"msgtype"`
	FeishuMsgType string        `json:"msg_type"`
	Title         string        `json:"title"`
	Text          textContent   `json:"text"`
	Content       feishuContent `json:"content"`
	Message       string        `json:"message"`
}

// Send validates webhookURL and posts a universal DingTalk/Feishu/WeCom/Slack JSON notification.
func (s *Sender) Send(ctx context.Context, webhookURL, title, body string) error {
	if ctx == nil {
		ctx = context.Background()
	}
	u, err := ValidateTarget(webhookURL, s.allowPrivate())
	if err != nil {
		return err
	}
	if u == "" {
		return errors.New("Webhook 地址不能为空")
	}

	hostname := ""
	if s != nil {
		hostname = s.Hostname
	}
	text := fmt.Sprintf("【CertDNS %s】\n主机: %s\n%s\n时间: %s",
		title, hostname, body, time.Now().Format("2006-01-02 15:04:05"))

	raw, err := json.Marshal(universalPayload{
		MsgType:       "text",
		FeishuMsgType: "text",
		Title:         title,
		Text:          textContent{Content: text},
		Content:       feishuContent{Text: text},
		Message:       text,
	})
	if err != nil {
		return err
	}

	timeout := s.timeout()
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, u, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	transport := &http.Transport{
		DialContext:       s.dialContext,
		DisableKeepAlives: true,
	}
	defer transport.CloseIdleConnections()

	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) > maxRedirects {
				return fmt.Errorf("Webhook 重定向次数超过上限 (%d)", maxRedirects)
			}
			_, err := ValidateTarget(req.URL.String(), s.allowPrivate())
			return err
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 400 {
		return fmt.Errorf("Webhook 响应状态码 %d", resp.StatusCode)
	}
	return nil
}
