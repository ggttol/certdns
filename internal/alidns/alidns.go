// Package alidns is an Alibaba Cloud DNS (RPC 2015-01-09) client supporting
// both Alibaba Cloud China (alidns.aliyuncs.com) and Alibaba Cloud
// International (alidns.ap-southeast-1.aliyuncs.com) as well as custom regions.
package alidns

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"certdns/internal/domain"
)

const (
	EditionCN     = "cn"
	EditionIntl   = "intl"
	EditionCustom = "custom"

	DefaultCNEndpoint   = "https://alidns.aliyuncs.com/"
	DefaultIntlEndpoint = "https://alidns.ap-southeast-1.aliyuncs.com/"

	DefaultCNRegion   = "cn-hangzhou"
	DefaultIntlRegion = "ap-southeast-1"
)

// ResolveEndpoint returns the normalized endpoint URL and region ID for an edition.
func ResolveEndpoint(edition, endpoint, regionID string) (string, string, string) {
	switch edition {
	case EditionIntl:
		if endpoint == "" {
			endpoint = DefaultIntlEndpoint
		}
		if regionID == "" {
			regionID = DefaultIntlRegion
		}
		return EditionIntl, normalizeEndpoint(endpoint), regionID
	case EditionCustom:
		if endpoint == "" {
			endpoint = DefaultCNEndpoint
		}
		if regionID == "" {
			regionID = DefaultCNRegion
		}
		return EditionCustom, normalizeEndpoint(endpoint), regionID
	default:
		return EditionCN, DefaultCNEndpoint, DefaultCNRegion
	}
}

func normalizeEndpoint(ep string) string {
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return DefaultCNEndpoint
	}
	if !strings.HasPrefix(ep, "http://") && !strings.HasPrefix(ep, "https://") {
		ep = "https://" + ep
	}
	if !strings.HasSuffix(ep, "/") {
		ep += "/"
	}
	return ep
}

// MaskKey masks an AccessKey ID for display (e.g. "LTAI5t...FneE").
func MaskKey(key string) string {
	if len(key) <= 10 {
		return key
	}
	return key[:6] + "••••" + key[len(key)-4:]
}

// Credentials holds an AccessKey pair and optional endpoint/region configuration.
type Credentials struct {
	KeyID    string
	Secret   string
	Edition  string
	RegionID string
	Endpoint string
}

// Client talks to AliDNS. Endpoint can be overridden for tests or international accounts.
type Client struct {
	Creds    Credentials
	Endpoint string
	RegionID string
	Lang     string
	HTTP     *http.Client
}

func New(creds Credentials) *Client {
	ed, ep, reg := ResolveEndpoint(creds.Edition, creds.Endpoint, creds.RegionID)
	lang := "zh"
	if ed == EditionIntl {
		lang = "en"
	}
	return &Client{
		Creds:    creds,
		Endpoint: ep,
		RegionID: reg,
		Lang:     lang,
		HTTP:     &http.Client{Timeout: 25 * time.Second},
	}
}

// Error is a provider rejection. Messages never contain credentials.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string {
	if e.Code == "" {
		return "阿里云 DNS 请求失败: " + e.Message
	}
	return "阿里云 DNS 拒绝请求 (" + e.Code + ")"
}

var safeCodeRE = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)

func percent(value string) string {
	return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(
		url.QueryEscape(value), "+", "%20"), "*", "%2A"), "%7E", "~")
}

func nonce() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (c *Client) sign(action string, args map[string]string) url.Values {
	params := map[string]string{
		"Action":           action,
		"Format":           "JSON",
		"Version":          "2015-01-09",
		"AccessKeyId":      c.Creds.KeyID,
		"SignatureMethod":  "HMAC-SHA1",
		"SignatureVersion": "1.0",
		"SignatureNonce":   nonce(),
		"Timestamp":        time.Now().UTC().Format("2006-01-02T15:04:05Z"),
	}
	if c.RegionID != "" {
		params["RegionId"] = c.RegionID
	}
	if c.Lang != "" {
		params["Lang"] = c.Lang
	}
	for k, v := range args {
		params[k] = v
	}
	keys := make([]string, 0, len(params))
	for k := range params {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = percent(k) + "=" + percent(params[k])
	}
	mac := hmac.New(sha1.New, []byte(c.Creds.Secret+"&"))
	mac.Write([]byte("POST&%2F&" + percent(strings.Join(parts, "&"))))
	values := url.Values{}
	for k, v := range params {
		values.Set(k, v)
	}
	values.Set("Signature", base64.StdEncoding.EncodeToString(mac.Sum(nil)))
	return values
}

// Call performs an RPC action and decodes the JSON response into out.
func (c *Client) Call(ctx context.Context, action string, args map[string]string, out any) error {
	if c.Creds.KeyID == "" || c.Creds.Secret == "" {
		return &Error{Code: "MissingCredentials"}
	}
	body := c.sign(action, args).Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint, strings.NewReader(body))
	if err != nil {
		return &Error{Message: "无法创建请求"}
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return &Error{Message: "网络连接失败"}
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return &Error{Message: "读取响应失败"}
	}
	var envelope struct {
		Code    string `json:"Code"`
		Message string `json:"Message"`
	}
	_ = json.Unmarshal(raw, &envelope)
	if resp.StatusCode != http.StatusOK || envelope.Code != "" {
		code := envelope.Code
		if !safeCodeRE.MatchString(code) {
			code = "HTTP" + strconv.Itoa(resp.StatusCode)
		}
		return &Error{Code: code}
	}
	if out != nil {
		if err := json.Unmarshal(raw, out); err != nil {
			return &Error{Message: "响应格式异常"}
		}
	}
	return nil
}

// Record is a DNS record as returned by AliDNS.
type Record struct {
	RecordID   string `json:"RecordId"`
	DomainName string `json:"DomainName"`
	RR         string `json:"RR"`
	Type       string `json:"Type"`
	Value      string `json:"Value"`
	TTL        int64  `json:"TTL"`
	Priority   int64  `json:"Priority"`
	Line       string `json:"Line"`
	Status     string `json:"Status"`
	Remark     string `json:"Remark"`
}

// Zones lists all domains hosted in AliDNS for the account.
func (c *Client) Zones(ctx context.Context) ([]string, error) {
	var zones []string
	for page := 1; ; page++ {
		var res struct {
			TotalCount int64 `json:"TotalCount"`
			Domains    struct {
				Domain []struct {
					DomainName string `json:"DomainName"`
				} `json:"Domain"`
			} `json:"Domains"`
		}
		err := c.Call(ctx, "DescribeDomains", map[string]string{
			"PageNumber": strconv.Itoa(page), "PageSize": "100"}, &res)
		if err != nil {
			return nil, err
		}
		for _, d := range res.Domains.Domain {
			if name, err := domain.Normalize(d.DomainName, false); err == nil {
				zones = append(zones, name)
			}
		}
		if int64(page*100) >= res.TotalCount {
			break
		}
		if len(res.Domains.Domain) == 0 {
			return nil, &Error{Message: "域名分页不完整"}
		}
	}
	sort.Strings(zones)
	return zones, nil
}

// RecordQuery filters DescribeDomainRecords.
type RecordQuery struct {
	Zone     string
	Page     int
	PageSize int
	RRKey    string
	TypeKey  string
	Keyword  string
}

// Records returns one page of records and the total count.
func (c *Client) Records(ctx context.Context, q RecordQuery) ([]Record, int64, error) {
	args := map[string]string{
		"DomainName": q.Zone,
		"PageNumber": strconv.Itoa(q.Page),
		"PageSize":   strconv.Itoa(q.PageSize),
	}
	if q.RRKey != "" {
		args["RRKeyWord"] = q.RRKey
	}
	if q.TypeKey != "" {
		args["TypeKeyWord"] = q.TypeKey
	}
	if q.Keyword != "" {
		args["KeyWord"] = q.Keyword
	}
	var res struct {
		TotalCount    int64 `json:"TotalCount"`
		DomainRecords struct {
			Record []Record `json:"Record"`
		} `json:"DomainRecords"`
	}
	if err := c.Call(ctx, "DescribeDomainRecords", args, &res); err != nil {
		return nil, 0, err
	}
	return res.DomainRecords.Record, res.TotalCount, nil
}

// AllRecords pages through every record matching the query.
func (c *Client) AllRecords(ctx context.Context, q RecordQuery) ([]Record, error) {
	var all []Record
	q.PageSize = 500
	for q.Page = 1; ; q.Page++ {
		items, total, err := c.Records(ctx, q)
		if err != nil {
			return nil, err
		}
		all = append(all, items...)
		if int64(q.Page*q.PageSize) >= total {
			return all, nil
		}
		if len(items) == 0 {
			return nil, &Error{Message: "记录分页不完整"}
		}
	}
}

func (c *Client) RecordInfo(ctx context.Context, id string) (*Record, error) {
	var r Record
	if err := c.Call(ctx, "DescribeDomainRecordInfo", map[string]string{"RecordId": id}, &r); err != nil {
		return nil, err
	}
	return &r, nil
}

// RecordInput describes a record to create or update.
type RecordInput struct {
	RR       string
	Type     string
	Value    string
	TTL      int64
	Priority int64
	Line     string
}

func (in RecordInput) args() map[string]string {
	args := map[string]string{
		"RR":    in.RR,
		"Type":  in.Type,
		"Value": in.Value,
		"TTL":   strconv.FormatInt(in.TTL, 10),
	}
	if in.Type == "MX" {
		args["Priority"] = strconv.FormatInt(in.Priority, 10)
	}
	if in.Line != "" {
		args["Line"] = in.Line
	}
	return args
}

func (c *Client) AddRecord(ctx context.Context, zone string, in RecordInput) (string, error) {
	args := in.args()
	args["DomainName"] = zone
	var res struct {
		RecordID string `json:"RecordId"`
	}
	if err := c.Call(ctx, "AddDomainRecord", args, &res); err != nil {
		return "", err
	}
	return res.RecordID, nil
}

func (c *Client) UpdateRecord(ctx context.Context, id string, in RecordInput) error {
	args := in.args()
	args["RecordId"] = id
	return c.Call(ctx, "UpdateDomainRecord", args, nil)
}

func (c *Client) SetRecordStatus(ctx context.Context, id string, enabled bool) error {
	status := "Disable"
	if enabled {
		status = "Enable"
	}
	return c.Call(ctx, "SetDomainRecordStatus", map[string]string{"RecordId": id, "Status": status}, nil)
}

func (c *Client) UpdateRecordRemark(ctx context.Context, id, remark string) error {
	args := map[string]string{"RecordId": id}
	if remark != "" {
		args["Remark"] = remark
	}
	return c.Call(ctx, "UpdateDomainRecordRemark", args, nil)
}

func (c *Client) DeleteRecord(ctx context.Context, id string) error {
	return c.Call(ctx, "DeleteDomainRecord", map[string]string{"RecordId": id}, nil)
}

// AddDomain enables DNS hosting for a zone and returns the assigned nameservers.
func (c *Client) AddDomain(ctx context.Context, zone string) ([]string, error) {
	var res struct {
		DNSServers struct {
			DNSServer []string `json:"DnsServer"`
		} `json:"DnsServers"`
	}
	if err := c.Call(ctx, "AddDomain", map[string]string{"DomainName": zone}, &res); err != nil {
		return nil, err
	}
	return res.DNSServers.DNSServer, nil
}

// IsRecordNotFound reports whether err indicates that the DNS record or domain does not exist.
func IsRecordNotFound(err error) bool {
	var e *Error
	if !errors.As(err, &e) || e.Code == "" {
		return false
	}
	code := strings.ToLower(e.Code)
	if strings.Contains(code, "accesskey") || strings.Contains(code, "signature") {
		return false
	}
	return code == "domainrecordnotbelongtouser" ||
		code == "domainnotfound" ||
		strings.Contains(code, "noexist") ||
		strings.Contains(code, "notexist") ||
		strings.Contains(code, "recordid.notfound")
}

// Hint converts a provider error into an actionable Chinese message.
func Hint(err error) string {
	var e *Error
	if !errors.As(err, &e) {
		return "阿里云 DNS 请求失败，请检查网络后重试"
	}
	if e.Code == "" {
		return e.Error()
	}
	code := strings.ToLower(e.Code)
	switch {
	case e.Code == "MissingCredentials":
		return "请先在“阿里云账户”中配置有效的 AccessKey"
	case strings.Contains(code, "forbidden") || strings.Contains(code, "permission") ||
		strings.Contains(code, "accesskey") || strings.Contains(code, "signature") ||
		strings.Contains(code, "unauthorized"):
		return fmt.Sprintf("AccessKey 无效、版本不匹配或 RAM 权限不足 (%s)", e.Code)
	case strings.Contains(code, "throttl") || strings.Contains(code, "frequency") || strings.Contains(code, "flowcontrol"):
		return fmt.Sprintf("阿里云接口限流，请稍后重试 (%s)", e.Code)
	case strings.Contains(code, "ttl"):
		return fmt.Sprintf("TTL 不被当前解析版本支持，免费版最小 600 秒 (%s)", e.Code)
	case IsRecordNotFound(err):
		return fmt.Sprintf("解析记录或域名不存在 (%s)", e.Code)
	case strings.Contains(code, "duplicate") || strings.Contains(code, "exist"):
		return fmt.Sprintf("记录或域名已存在 (%s)", e.Code)
	case strings.Contains(code, "conflict"):
		return fmt.Sprintf("与已有记录冲突，例如 CNAME 不能与其他记录共存 (%s)", e.Code)
	default:
		return fmt.Sprintf("请检查域名和记录值后重试 (%s)", e.Code)
	}
}
