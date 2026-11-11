package web

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"certdns/internal/certx"
	"certdns/internal/domain"
	"certdns/internal/store"
)

func normalizeAllowedDomains(raw []string) ([]string, error) {
	if len(raw) == 0 {
		return []string{"*"}, nil
	}
	var out []string
	seen := map[string]bool{}
	for _, item := range raw {
		for _, part := range strings.FieldsFunc(item, func(r rune) bool {
			return r == ',' || r == ';' || unicode.IsSpace(r)
		}) {
			p := strings.ToLower(strings.TrimSpace(part))
			if p == "" {
				continue
			}
			if p != "*" {
				norm, err := domain.Normalize(p, true)
				if err != nil {
					return nil, fail(http.StatusBadRequest, "授权域名格式无效: %s", part)
				}
				p = norm
			}
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
		}
	}
	if len(out) == 0 {
		out = []string{"*"}
	}
	return out, nil
}

func (s *Server) listAPITokens(w http.ResponseWriter, r *http.Request) error {
	tokens, err := s.Store.APITokens(r.Context())
	if err != nil {
		return err
	}
	if tokens == nil {
		tokens = []*store.APIToken{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"tokens": tokens})
	return nil
}

func (s *Server) createAPIToken(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Name           string   `json:"name"`
		AllowedDomains []string `json:"allowed_domains"`
	}
	if err := decode(w, r, &b); err != nil {
		return err
	}
	name := strings.TrimSpace(b.Name)
	if name == "" || utf8.RuneCountInString(name) > 64 {
		return fail(http.StatusBadRequest, "请输入 1-64 字符的令牌名称（如服务器名 edge-node-01）")
	}
	allowed, err := normalizeAllowedDomains(b.AllowedDomains)
	if err != nil {
		return err
	}
	tok, plain, err := s.Store.CreateAPIToken(r.Context(), name, allowed)
	if errors.Is(err, store.ErrDuplicate) {
		return fail(http.StatusConflict, "同名 API 令牌已存在")
	}
	if err != nil {
		return err
	}
	s.audit(r, "token.create", tok.Name, fmt.Sprintf("domains=%v, prefix=%s", tok.AllowedDomains, tok.TokenPrefix))
	writeJSON(w, http.StatusCreated, map[string]any{
		"token":     tok,
		"plaintext": plain,
	})
	return nil
}

func (s *Server) updateAPIToken(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return fail(http.StatusNotFound, "API 令牌不存在")
	}
	existing, err := s.Store.APIToken(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "API 令牌不存在")
	}
	if err != nil {
		return err
	}
	var b struct {
		Name           *string  `json:"name"`
		AllowedDomains []string `json:"allowed_domains"`
		Enabled        *bool    `json:"enabled"`
	}
	if err := decode(w, r, &b); err != nil {
		return err
	}
	name := existing.Name
	if b.Name != nil {
		trimmed := strings.TrimSpace(*b.Name)
		if trimmed == "" || utf8.RuneCountInString(trimmed) > 64 {
			return fail(http.StatusBadRequest, "请输入 1-64 字符的令牌名称")
		}
		name = trimmed
	}
	allowed := existing.AllowedDomains
	if b.AllowedDomains != nil {
		allowed, err = normalizeAllowedDomains(b.AllowedDomains)
		if err != nil {
			return err
		}
	}
	enabled := existing.Enabled
	if b.Enabled != nil {
		enabled = *b.Enabled
	}
	tok, err := s.Store.UpdateAPIToken(r.Context(), id, name, allowed, enabled)
	if errors.Is(err, store.ErrDuplicate) {
		return fail(http.StatusConflict, "同名 API 令牌已存在")
	}
	if err != nil {
		return err
	}
	s.audit(r, "token.update", tok.Name, fmt.Sprintf("enabled=%v, domains=%v", tok.Enabled, tok.AllowedDomains))
	writeJSON(w, http.StatusOK, map[string]any{"token": tok})
	return nil
}

func (s *Server) deleteAPIToken(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return fail(http.StatusNotFound, "API 令牌不存在")
	}
	existing, err := s.Store.APIToken(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "API 令牌不存在")
	}
	if err != nil {
		return err
	}
	if err := s.Store.DeleteAPIToken(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, "token.delete", existing.Name, existing.TokenPrefix)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
	return nil
}

type pullCandidate struct {
	cert     *store.Certificate
	notAfter time.Time
	files    map[string][]byte
	sha256   string
}

func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := range 64 {
		c := s[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

func certFingerprint(c *store.Certificate, certPEM []byte) string {
	if c != nil && isHex64(c.SHA256) {
		return strings.ToLower(c.SHA256)
	}
	if leaf, err := certx.InspectLeaf(certPEM); err == nil {
		return certx.ExtractMetadata(leaf, "").SHA256
	}
	sum := sha256.Sum256(certPEM)
	return hex.EncodeToString(sum[:])
}

func (s *Server) checkPullable(c *store.Certificate, now time.Time) (*pullCandidate, bool) {
	if c == nil || c.Staging || len(c.Domains) == 0 {
		return nil, false
	}
	if c.Status != "valid" && c.Status != "renewing" {
		return nil, false
	}
	notAfter, err := time.Parse(time.RFC3339, c.NotAfter)
	if err != nil || !now.Before(notAfter) {
		return nil, false
	}
	files, err := s.Manager.ReadFiles(c.ID)
	if err != nil {
		return nil, false
	}
	return &pullCandidate{
		cert:     c,
		notAfter: notAfter,
		files:    files,
		sha256:   certFingerprint(c, files["cert.pem"]),
	}, true
}

func parsePullFileKind(raw string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "":
		return "json", nil
	case "fullchain", "fullchain.pem":
		return "fullchain", nil
	case "privkey", "privkey.pem", "key":
		return "privkey", nil
	case "cert", "cert.pem":
		return "cert", nil
	case "chain", "chain.pem":
		return "chain", nil
	case "bundle", "haproxy":
		return "bundle", nil
	default:
		return "", fail(http.StatusBadRequest, "不支持的 file 参数（可选: fullchain, privkey, cert, chain, bundle）")
	}
}

func ifNoneMatchHit(headerValues []string, fp string) bool {
	if len(headerValues) == 0 || !isHex64(fp) {
		return false
	}
	for _, raw := range headerValues {
		for _, part := range strings.Split(raw, ",") {
			tag := strings.TrimSpace(part)
			if tag == "" {
				continue
			}
			if tag == "*" {
				return true
			}
			if strings.HasPrefix(tag, "W/") || strings.HasPrefix(tag, "w/") {
				tag = strings.TrimSpace(tag[2:])
			}
			if len(tag) >= 2 && strings.HasPrefix(tag, `"`) && strings.HasSuffix(tag, `"`) {
				tag = tag[1 : len(tag)-1]
			}
			if len(tag) == 64 && strings.EqualFold(tag, fp) {
				return true
			}
		}
	}
	return false
}

func ensureTrailingNewline(b []byte) []byte {
	trimmed := bytes.TrimSpace(b)
	if len(trimmed) == 0 {
		return []byte{}
	}
	out := make([]byte, len(trimmed)+1)
	copy(out, trimmed)
	out[len(trimmed)] = '\n'
	return out
}

func buildPEMBundle(fullchain, privkey []byte) []byte {
	fc := bytes.TrimSpace(fullchain)
	pk := bytes.TrimSpace(privkey)
	var buf bytes.Buffer
	buf.Grow(len(fc) + len(pk) + 2)
	if len(fc) > 0 {
		buf.Write(fc)
		buf.WriteByte('\n')
	}
	if len(pk) > 0 {
		buf.Write(pk)
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

func (s *Server) pullListCertificates(w http.ResponseWriter, r *http.Request) error {
	tok := currentAPIToken(r)
	certs, err := s.Store.Certificates(r.Context())
	if err != nil {
		return err
	}
	type item struct {
		ID            string   `json:"id"`
		PrimaryDomain string   `json:"primary_domain"`
		Domains       []string `json:"domains"`
		KeyType       string   `json:"key_type"`
		NotBefore     string   `json:"not_before"`
		NotAfter      string   `json:"not_after"`
		Issuer        string   `json:"issuer"`
		SHA256        string   `json:"sha256"`
		UpdatedAt     string   `json:"updated_at"`
	}
	now := time.Now()
	out := []item{}
	for _, c := range certs {
		if !tok.AllowsCertificate(c.Domains) {
			continue
		}
		cand, ok := s.checkPullable(c, now)
		if !ok {
			continue
		}
		out = append(out, item{
			ID:            c.ID,
			PrimaryDomain: c.Domains[0],
			Domains:       c.Domains,
			KeyType:       c.KeyType,
			NotBefore:     c.NotBefore,
			NotAfter:      c.NotAfter,
			Issuer:        c.Issuer,
			SHA256:        cand.sha256,
			UpdatedAt:     c.UpdatedAt,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
	return nil
}

func (s *Server) pullCertificateByDomain(w http.ResponseWriter, r *http.Request) error {
	tok := currentAPIToken(r)
	rawDomain := strings.ToLower(strings.TrimSpace(r.PathValue("domain")))
	target, err := domain.Normalize(rawDomain, true)
	if err != nil {
		return fail(http.StatusBadRequest, "请求的域名无效: %s", rawDomain)
	}
	if !tok.AllowsDomain(target) {
		return fail(http.StatusForbidden, "当前 API Token 无权拉取域名 %s 的证书", target)
	}

	mw := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("match_wildcard")))
	allowWildcard := mw == "1" || mw == "true"

	certs, err := s.Store.Certificates(r.Context())
	if err != nil {
		return err
	}
	now := time.Now()
	var best *pullCandidate
	bestScore := 0
	matchedAny := false

	for _, c := range certs {
		score := domain.MatchScore(c.Domains, target, allowWildcard)
		if score == 0 {
			continue
		}
		cand, ok := s.checkPullable(c, now)
		if !ok {
			continue
		}
		matchedAny = true
		if !tok.AllowsCertificate(c.Domains) {
			continue
		}
		if best == nil || score > bestScore || (score == bestScore && cand.notAfter.After(best.notAfter)) {
			best = cand
			bestScore = score
		}
	}

	if best == nil {
		if matchedAny {
			return fail(http.StatusForbidden, "当前 API Token 未获授权覆盖该证书包含的全部域名")
		}
		return fail(http.StatusNotFound, "未找到域名 %s 的有效证书", target)
	}

	canonicalKind, err := parsePullFileKind(r.URL.Query().Get("file"))
	if err != nil {
		return err
	}

	fp := best.sha256
	etag := `"` + fp + `"`
	if ifNoneMatchHit(r.Header.Values("If-None-Match"), fp) {
		w.Header().Set("ETag", etag)
		w.WriteHeader(http.StatusNotModified)
		return nil
	}

	w.Header().Set("ETag", etag)
	s.Store.AddAudit(r.Context(), "token:"+tok.Name, clientIP(r), "cert.pull", target,
		fmt.Sprintf("file=%s, sha256=%s", canonicalKind, fp[:12]))

	if canonicalKind != "json" {
		var body []byte
		switch canonicalKind {
		case "fullchain":
			body = best.files["fullchain.pem"]
		case "privkey":
			body = ensureTrailingNewline(best.files["privkey.pem"])
		case "cert":
			body = best.files["cert.pem"]
		case "chain":
			body = best.files["chain.pem"]
		case "bundle":
			body = buildPEMBundle(best.files["fullchain.pem"], best.files["privkey.pem"])
		}
		w.Header().Set("Content-Type", "application/x-pem-file; charset=utf-8")
		w.Header().Set("X-Certificate-SHA256", fp)
		w.Header().Set("X-Certificate-Not-After", best.cert.NotAfter)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(body)
		return nil
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"id":            best.cert.ID,
		"domain":        target,
		"domains":       best.cert.Domains,
		"key_type":      best.cert.KeyType,
		"not_before":    best.cert.NotBefore,
		"not_after":     best.cert.NotAfter,
		"issuer":        best.cert.Issuer,
		"sha256":        fp,
		"updated_at":    best.cert.UpdatedAt,
		"cert_pem":      string(best.files["cert.pem"]),
		"chain_pem":     string(best.files["chain.pem"]),
		"fullchain_pem": string(best.files["fullchain.pem"]),
		"privkey_pem":   string(ensureTrailingNewline(best.files["privkey.pem"])),
	})
	return nil
}
