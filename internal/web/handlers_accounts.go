package web

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"certdns/internal/alidns"
	"certdns/internal/issuer"
	"certdns/internal/store"
)

var (
	keyIDRE  = regexp.MustCompile(`^[A-Za-z0-9_-]{6,256}$`)
	secretRE = regexp.MustCompile(`^[A-Za-z0-9_+/.=-]{1,256}$`)
	emailRE  = regexp.MustCompile(`^[^\s@]+@[^\s@]+\.[^\s@]+$`)
)

type accountInput struct {
	Name      string `json:"name"`
	Edition   string `json:"edition"`   // "cn", "intl", "custom"
	RegionID  string `json:"region_id"` // e.g. "cn-hangzhou", "ap-southeast-1"
	Endpoint  string `json:"endpoint"`
	KeyID     string `json:"access_key_id"`
	Secret    string `json:"access_key_secret"`
	Email     string `json:"email"`
	IsDefault *bool  `json:"is_default"`
	Enabled   *bool  `json:"enabled"`
}

func (in *accountInput) validate(requireSecret bool) error {
	in.Name = strings.TrimSpace(in.Name)
	in.KeyID = strings.TrimSpace(in.KeyID)
	in.Email = strings.TrimSpace(in.Email)
	in.Endpoint = strings.TrimSpace(in.Endpoint)
	in.RegionID = strings.TrimSpace(in.RegionID)
	if in.Name == "" || len(in.Name) > 64 {
		return fail(http.StatusBadRequest, "请填写账户名称（1-64 个字符）")
	}
	if in.Edition == "" {
		in.Edition = alidns.EditionCN
	}
	if in.Edition != alidns.EditionCN && in.Edition != alidns.EditionIntl && in.Edition != alidns.EditionCustom {
		return fail(http.StatusBadRequest, "账户站点类型无效（可选 cn / intl / custom）")
	}
	if !keyIDRE.MatchString(in.KeyID) {
		return fail(http.StatusBadRequest, "AccessKey ID 格式无效")
	}
	if requireSecret && in.Secret == "" {
		return fail(http.StatusBadRequest, "请填写 AccessKey Secret")
	}
	if in.Secret != "" && !secretRE.MatchString(in.Secret) {
		return fail(http.StatusBadRequest, "AccessKey Secret 格式无效")
	}
	if in.Email != "" && (len(in.Email) > 254 || !emailRE.MatchString(in.Email)) {
		return fail(http.StatusBadRequest, "邮箱格式无效")
	}
	return nil
}

func redactAccountForRole(a *store.DNSAccount, role string) *store.DNSAccount {
	if a == nil {
		return nil
	}
	cp := *a
	if role != "admin" {
		cp.AccessKeyID = ""
	}
	return &cp
}

func redactAccountsForRole(accts []*store.DNSAccount, role string) []*store.DNSAccount {
	out := make([]*store.DNSAccount, 0, len(accts))
	for _, a := range accts {
		out = append(out, redactAccountForRole(a, role))
	}
	return out
}

func (s *Server) listAccounts(w http.ResponseWriter, r *http.Request) error {
	accts, err := s.Store.DNSAccounts(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"accounts": redactAccountsForRole(accts, userRole(r)),
	})
	return nil
}

func (s *Server) createAccount(w http.ResponseWriter, r *http.Request) error {
	var in accountInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := in.validate(true); err != nil {
		return err
	}
	acct, err := s.Store.CreateDNSAccount(r.Context(), &store.DNSAccount{
		Name:            in.Name,
		Edition:         in.Edition,
		RegionID:        in.RegionID,
		Endpoint:        in.Endpoint,
		AccessKeyID:     in.KeyID,
		AccessKeySecret: in.Secret,
		Email:           in.Email,
		IsDefault:       in.IsDefault != nil && *in.IsDefault,
		Enabled:         in.Enabled == nil || *in.Enabled,
	})
	if errors.Is(err, store.ErrDuplicate) {
		return fail(http.StatusConflict, "同名阿里云账户已存在")
	}
	if err != nil {
		return err
	}
	// Proactively sync zones on creation (non-fatal if offline in isolated tests).
	_, _ = s.Manager.SyncAccountZones(r.Context(), acct)
	if refreshed, err := s.Store.DNSAccount(r.Context(), acct.ID); err == nil && refreshed != nil {
		acct = refreshed
	}
	s.audit(r, "account.create", acct.Name, fmt.Sprintf("站点: %s, Key: %s", acct.Edition, acct.MaskedKeyID))
	writeJSON(w, http.StatusCreated, redactAccountForRole(acct, userRole(r)))
	return nil
}

func (s *Server) updateAccount(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return fail(http.StatusNotFound, "账户不存在")
	}
	cur, err := s.Store.DNSAccount(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "账户不存在")
	}
	if err != nil {
		return err
	}
	var in accountInput
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if err := in.validate(false); err != nil {
		return err
	}
	if in.Secret == "" && in.KeyID != cur.AccessKeyID {
		return fail(http.StatusBadRequest, "更换 AccessKey ID 时必须同时提供新的 AccessKey Secret")
	}
	isDefault := cur.IsDefault
	if in.IsDefault != nil {
		isDefault = *in.IsDefault
	}
	enabled := cur.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	acct, err := s.Store.UpdateDNSAccount(r.Context(), id, &store.DNSAccount{
		Name:            in.Name,
		Edition:         in.Edition,
		RegionID:        in.RegionID,
		Endpoint:        in.Endpoint,
		AccessKeyID:     in.KeyID,
		AccessKeySecret: in.Secret,
		Email:           in.Email,
		IsDefault:       isDefault,
		Enabled:         enabled,
	})
	if errors.Is(err, store.ErrDuplicate) {
		return fail(http.StatusConflict, "同名阿里云账户已存在")
	}
	if err != nil {
		return err
	}
	s.audit(r, "account.update", acct.Name, fmt.Sprintf("站点: %s, 默认: %v, 启用: %v", acct.Edition, acct.IsDefault, acct.Enabled))
	writeJSON(w, http.StatusOK, redactAccountForRole(acct, userRole(r)))
	return nil
}

func (s *Server) deleteAccount(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return fail(http.StatusNotFound, "账户不存在")
	}
	cur, err := s.Store.DNSAccount(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "账户不存在")
	}
	if err != nil {
		return err
	}
	if err := s.Store.DeleteDNSAccount(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, "account.delete", cur.Name, cur.MaskedKeyID)
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	return nil
}

func (s *Server) testAccount(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return fail(http.StatusNotFound, "账户不存在")
	}
	acct, err := s.Store.DNSAccount(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "账户不存在")
	}
	if err != nil {
		return err
	}
	zones, err := s.Manager.SyncAccountZones(r.Context(), acct)
	if err != nil {
		return err
	}
	if zones == nil {
		zones = []string{}
	}
	updated, err := s.Store.DNSAccount(r.Context(), id)
	if err != nil || updated == nil {
		updated = acct
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"zones":   zones,
		"account": redactAccountForRole(updated, userRole(r)),
	})
	return nil
}

func (s *Server) syncAllAccounts(w http.ResponseWriter, r *http.Request) error {
	items, err := s.Manager.ListZoneOwners(r.Context(), "", true)
	if err != nil {
		return err
	}
	if items == nil {
		items = []issuer.ZoneOwner{}
	}
	accts, err := s.Store.DNSAccounts(r.Context())
	if err != nil {
		return err
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"items":    items,
		"accounts": redactAccountsForRole(accts, userRole(r)),
	})
	return nil
}
