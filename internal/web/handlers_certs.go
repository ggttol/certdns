package web

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"certdns/internal/certx"
	"certdns/internal/domain"
	"certdns/internal/store"
)

type certView struct {
	*store.Certificate
	AccountName string `json:"account_name"`
	DaysLeft    *int   `json:"days_left"`
	InUse       bool   `json:"in_use"`
	UsedBy      string `json:"used_by,omitempty"`
	ActiveJob   bool   `json:"active_job"`
}

func (s *Server) formatCertView(c *store.Certificate, now time.Time, tlsCertID string, activeJob bool, acctNames map[string]string) certView {
	cp := *c
	effStatus, daysLeft := certx.EffectiveStatus(cp.Status, cp.NotAfter, now)
	cp.Status = effStatus
	v := certView{
		Certificate: &cp,
		DaysLeft:    daysLeft,
		ActiveJob:   activeJob,
	}
	if cp.AccountID != "" {
		v.AccountName = acctNames[cp.AccountID]
	}
	if tlsCertID != "" && cp.ID == tlsCertID {
		v.InUse = true
		v.UsedBy = s.Manager.Hostname
	}
	return v
}

func (s *Server) singleCertView(ctx context.Context, c *store.Certificate) certView {
	active, _ := s.Store.HasActiveJob(ctx, c.ID)
	return s.formatCertView(c, time.Now(), s.Manager.TLSCertID(ctx), active, s.accountNameMap(ctx))
}

func (s *Server) accountNameMap(ctx context.Context) map[string]string {
	m := map[string]string{}
	accts, _ := s.Store.DNSAccounts(ctx)
	for _, a := range accts {
		m[a.ID] = a.Name
	}
	return m
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	certs, err := s.Store.Certificates(ctx)
	if err != nil {
		return err
	}
	tlsCertID := s.Manager.TLSCertID(ctx)
	activeMap, err := s.Store.ActiveJobCertIDs(ctx)
	if err != nil {
		return err
	}
	names := s.accountNameMap(ctx)
	now := time.Now()
	out := make([]certView, 0, len(certs))
	for _, c := range certs {
		out = append(out, s.formatCertView(c, now, tlsCertID, activeMap[c.ID], names))
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": out})
	return nil
}

func (s *Server) loadCert(r *http.Request) (*store.Certificate, error) {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return nil, fail(http.StatusNotFound, "证书不存在")
	}
	c, err := s.Store.Certificate(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return nil, fail(http.StatusNotFound, "证书不存在")
	}
	return c, err
}

func normalizeDomains(raw []string) ([]string, error) {
	if len(raw) == 0 || len(raw) > 100 {
		return nil, fail(http.StatusBadRequest, "请提供 1-100 个域名")
	}
	seen := map[string]bool{}
	var out []string
	for _, d := range raw {
		n, err := domain.Normalize(d, true)
		if err != nil {
			return nil, fail(http.StatusBadRequest, "%s", err.Error())
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out, nil
}

var validKeyTypes = map[string]bool{"EC256": true, "EC384": true, "RSA2048": true, "RSA4096": true}

func (s *Server) issue(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Domains     []string `json:"domains"`
		Staging     bool     `json:"staging"`
		AcceptTerms bool     `json:"accept_terms"`
		AutoRenew   *bool    `json:"auto_renew"`
		AccountID   string   `json:"account_id"`
		KeyType     string   `json:"key_type"`
		Remark      string   `json:"remark"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	domains, err := normalizeDomains(in.Domains)
	if err != nil {
		return err
	}
	if !in.AcceptTerms {
		return fail(http.StatusBadRequest, "请先阅读并同意证书颁发机构的服务条款")
	}
	in.AccountID = strings.TrimSpace(in.AccountID)
	if in.AccountID != "" && !store.ValidID(in.AccountID) {
		return fail(http.StatusBadRequest, "指定的阿里云 DNS 账户不存在")
	}
	if in.KeyType == "" {
		in.KeyType = "EC256"
	} else {
		in.KeyType = strings.ToUpper(strings.TrimSpace(in.KeyType))
		if !validKeyTypes[in.KeyType] {
			return fail(http.StatusBadRequest, "不支持的密钥算法（可选 EC256 / EC384 / RSA2048 / RSA4096）")
		}
	}
	for _, d := range domains {
		if _, _, _, err := s.Manager.MatchDomainAccount(r.Context(), d, in.AccountID, false); err != nil {
			return fail(http.StatusBadRequest, "%s", err.Error())
		}
	}
	c := &store.Certificate{
		ID:        store.NewID(),
		Domains:   domains,
		Staging:   in.Staging,
		AutoRenew: in.AutoRenew == nil || *in.AutoRenew,
		AccountID: in.AccountID,
		KeyType:   in.KeyType,
		Source:    "acme",
		Remark:    strings.TrimSpace(in.Remark),
	}
	jobID, err := s.Store.CreateCertificateWithJob(r.Context(), c)
	if errors.Is(err, store.ErrDuplicate) {
		return fail(http.StatusConflict, "相同域名组合的证书已存在，请直接续期")
	}
	if err != nil {
		return err
	}
	s.audit(r, "cert.issue", strings.Join(domains, ","), fmt.Sprintf("算法: %s, 测试环境: %v", c.KeyType, c.Staging))
	s.Manager.Wake()
	writeJSON(w, http.StatusAccepted, map[string]string{"id": c.ID, "job_id": jobID})
	return nil
}

func (s *Server) uploadCertificate(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		FullchainPEM string `json:"fullchain_pem"`
		PrivkeyPEM   string `json:"privkey_pem"`
		Remark       string `json:"remark"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	leaf, files, meta, err := certx.ValidatePair([]byte(in.FullchainPEM), []byte(in.PrivkeyPEM))
	if err != nil {
		return fail(http.StatusBadRequest, "%s", err.Error())
	}
	rawDomains := leaf.DNSNames
	if len(rawDomains) == 0 && leaf.Subject.CommonName != "" {
		rawDomains = []string{leaf.Subject.CommonName}
	}
	domains, err := normalizeDomains(rawDomains)
	if err != nil {
		return fail(http.StatusBadRequest, "证书未包含有效的域名 SAN: %v", err)
	}
	cert := &store.Certificate{
		ID:        store.NewID(),
		Domains:   domains,
		Staging:   false,
		Status:    "valid",
		AutoRenew: false,
		KeyType:   meta.KeyType,
		Source:    "upload",
		Remark:    strings.TrimSpace(in.Remark),
		NotBefore: meta.NotBefore,
		NotAfter:  meta.NotAfter,
		Issuer:    meta.Issuer,
		SHA256:    meta.SHA256,
	}
	if err := s.Manager.WriteFiles(cert.ID, files); err != nil {
		return err
	}
	if err := s.Store.InsertCertificate(r.Context(), cert); err != nil {
		_ = s.Manager.RemoveFiles(cert.ID)
		if errors.Is(err, store.ErrDuplicate) {
			return fail(http.StatusConflict, "相同域名组合的证书已存在")
		}
		return err
	}
	_ = s.Manager.SyncTLS(r.Context())
	s.audit(r, "cert.upload", strings.Join(domains, ","), fmt.Sprintf("到期: %s", meta.NotAfter))
	writeJSON(w, http.StatusCreated, map[string]string{"id": cert.ID})
	return nil
}

func (s *Server) certificateDetail(w http.ResponseWriter, r *http.Request) error {
	c, err := s.loadCert(r)
	if err != nil {
		return err
	}
	out := map[string]any{"certificate": s.singleCertView(r.Context(), c)}
	if files, err := s.Manager.ReadFiles(c.ID); err == nil {
		if leaf, err := certx.InspectLeaf(files["cert.pem"]); err == nil {
			meta := certx.ExtractMetadata(leaf, c.KeyType)
			out["x509"] = map[string]any{
				"subject":    meta.Subject,
				"sans":       meta.SANs,
				"serial":     meta.Serial,
				"sha256":     strings.ToUpper(meta.SHA256),
				"key_type":   meta.KeyType,
				"signature":  meta.Signature,
				"not_before": meta.NotBefore,
				"not_after":  meta.NotAfter,
				"issuer":     meta.IssuerDN,
			}
		}
		if u := currentUser(r); u != nil && (u.Role == "admin" || u.Role == "operator") {
			out["pem"] = map[string]string{
				"cert":      string(files["cert.pem"]),
				"chain":     string(files["chain.pem"]),
				"fullchain": string(files["fullchain.pem"]),
				"privkey":   string(files["privkey.pem"]),
			}
		}
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) updateCertificate(w http.ResponseWriter, r *http.Request) error {
	c, err := s.loadCert(r)
	if err != nil {
		return err
	}
	var in struct {
		AutoRenew *bool   `json:"auto_renew"`
		AccountID *string `json:"account_id"`
		Remark    *string `json:"remark"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if in.AccountID != nil {
		trimmed := strings.TrimSpace(*in.AccountID)
		in.AccountID = &trimmed
	}
	if in.Remark != nil {
		trimmed := strings.TrimSpace(*in.Remark)
		in.Remark = &trimmed
	}
	if c.Source == "upload" {
		if in.AutoRenew != nil && *in.AutoRenew {
			return fail(http.StatusBadRequest, "外部上传的证书不支持开启自动续期")
		}
		if in.AccountID != nil && *in.AccountID != "" {
			return fail(http.StatusBadRequest, "外部上传的证书不支持绑定阿里云 DNS 账户")
		}
	}
	if in.AccountID != nil && *in.AccountID != "" {
		if !store.ValidID(*in.AccountID) {
			return fail(http.StatusBadRequest, "指定的阿里云 DNS 账户不存在")
		}
		if _, err := s.Store.DNSAccount(r.Context(), *in.AccountID); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				return fail(http.StatusBadRequest, "指定的阿里云 DNS 账户不存在")
			}
			return err
		}
	}
	if err := s.Store.UpdateCertificateMeta(r.Context(), c.ID, in.AutoRenew, in.AccountID, in.Remark); err != nil {
		if errors.Is(err, store.ErrNotFound) {
			return fail(http.StatusNotFound, "证书不存在")
		}
		return err
	}
	updated, err := s.Store.Certificate(r.Context(), c.ID)
	if err != nil {
		return err
	}
	s.audit(r, "cert.update", strings.Join(updated.Domains, ","),
		fmt.Sprintf("auto_renew=%v, account_id=%s, remark=%s", updated.AutoRenew, updated.AccountID, updated.Remark))
	writeJSON(w, http.StatusOK, s.singleCertView(r.Context(), updated))
	return nil
}

func (s *Server) renew(w http.ResponseWriter, r *http.Request) error {
	c, err := s.loadCert(r)
	if err != nil {
		return err
	}
	if c.Source == "upload" {
		return fail(http.StatusBadRequest, "外部上传的证书不支持 ACME 自动续期")
	}
	accts, _ := s.Store.DNSAccounts(r.Context())
	if len(accts) == 0 {
		return fail(http.StatusBadRequest, "请先配置至少一个阿里云 DNS 账户")
	}
	kind := "renew"
	if c.NotAfter == "" {
		kind = "issue"
	}
	jobID, err := s.Store.QueueJob(r.Context(), c.ID, kind, "manual")
	if errors.Is(err, store.ErrActiveJob) {
		return fail(http.StatusConflict, "该证书已有任务在排队或执行中")
	}
	if err != nil {
		return err
	}
	s.audit(r, "cert.renew", strings.Join(c.Domains, ","), "")
	s.Manager.Wake()
	writeJSON(w, http.StatusAccepted, map[string]string{"job_id": jobID})
	return nil
}

func (s *Server) deleteCertificate(w http.ResponseWriter, r *http.Request) error {
	c, err := s.loadCert(r)
	if err != nil {
		return err
	}
	if c.ID == s.Manager.TLSCertID(r.Context()) {
		return fail(http.StatusConflict, "该证书正用于管理入口 %s，不能删除。签发一张覆盖该域名的新证书后会自动切换。", s.Manager.Hostname)
	}
	if active, err := s.Store.HasActiveJob(r.Context(), c.ID); err != nil {
		return err
	} else if active {
		return fail(http.StatusConflict, "请等待当前任务结束后再删除")
	}
	if err := s.Store.DeleteCertificate(r.Context(), c.ID); err != nil {
		return err
	}
	if err := s.Manager.RemoveFiles(c.ID); err != nil {
		return err
	}
	s.audit(r, "cert.delete", strings.Join(c.Domains, ","), c.ID)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	return nil
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) error {
	c, err := s.loadCert(r)
	if err != nil {
		return err
	}
	files, err := s.Manager.ReadFiles(c.ID)
	if err != nil {
		return fail(http.StatusConflict, "证书文件尚未生成")
	}
	format := r.URL.Query().Get("format")
	var wanted []string
	switch format {
	case "nginx":
		wanted = []string{"fullchain.pem", "privkey.pem"}
	case "apache":
		wanted = []string{"cert.pem", "chain.pem", "privkey.pem"}
	default:
		wanted = []string{"cert.pem", "chain.pem", "fullchain.pem", "privkey.pem"}
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range wanted {
		f, err := zw.Create(name)
		if err != nil {
			return err
		}
		_, _ = f.Write(files[name])
	}
	info, _ := json.MarshalIndent(map[string]any{
		"domains":    c.Domains,
		"staging":    c.Staging,
		"key_type":   c.KeyType,
		"not_before": c.NotBefore,
		"not_after":  c.NotAfter,
		"issuer":     c.Issuer,
	}, "", "  ")
	f, _ := zw.Create("certificate-info.json")
	_, _ = f.Write(info)
	if err := zw.Close(); err != nil {
		return err
	}
	name := strings.ReplaceAll(strings.ReplaceAll(c.Domains[0], "*.", "wildcard."), "/", "_")
	for _, d := range c.Domains {
		if !strings.HasPrefix(d, "*.") {
			name = d
			break
		}
	}
	if c.Staging {
		name = "staging-" + name
	}
	if format == "nginx" || format == "apache" {
		name += "-" + format
	}
	name += "-" + time.Now().Format("20060102") + ".zip"
	s.audit(r, "cert.download", strings.Join(c.Domains, ","), format)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	_, _ = w.Write(buf.Bytes())
	return nil
}

func (s *Server) listJobs(w http.ResponseWriter, r *http.Request) error {
	jobs, err := s.Store.Jobs(r.Context(), 100)
	if err != nil {
		return err
	}
	if jobs == nil {
		jobs = []*store.Job{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"jobs": jobs})
	return nil
}

func (s *Server) job(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return fail(http.StatusNotFound, "任务不存在")
	}
	j, err := s.Store.Job(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "任务不存在")
	}
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, j)
	return nil
}
