package web

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"certdns/internal/alidns"
	"certdns/internal/domain"
	"certdns/internal/issuer"
	"certdns/internal/store"
)

var (
	recordTypes = map[string]bool{
		"A": true, "AAAA": true, "CNAME": true, "MX": true,
		"TXT": true, "SRV": true, "CAA": true, "NS": true,
	}
	recordIDRE = regexp.MustCompile(`^[0-9]{1,64}$`)
)

func zoneParam(v string) (string, error) {
	z, err := domain.Normalize(strings.TrimSpace(v), false)
	if err != nil {
		return "", fail(http.StatusBadRequest, "请选择有效的主域名")
	}
	return z, nil
}

func (s *Server) dnsForZone(ctx context.Context, zone, accountID string) (*store.DNSAccount, *alidns.Client, error) {
	accountID = strings.TrimSpace(accountID)
	if accountID != "" {
		if !store.ValidID(accountID) {
			return nil, nil, fail(http.StatusBadRequest, "指定的阿里云 DNS 账户无效")
		}
		return s.Manager.AccountClient(ctx, accountID)
	}
	acct, client, matchedZone, err := s.Manager.MatchDomainAccount(ctx, zone, "", false)
	if err == nil && matchedZone == zone {
		return acct, client, nil
	}
	return s.Manager.AccountClient(ctx, "")
}

func (s *Server) zones(w http.ResponseWriter, r *http.Request) error {
	accountID := strings.TrimSpace(r.URL.Query().Get("account_id"))
	if accountID != "" && !store.ValidID(accountID) {
		return fail(http.StatusBadRequest, "指定的阿里云 DNS 账户无效")
	}
	refresh := r.URL.Query().Get("refresh") == "1"
	items, err := s.Manager.ListZoneOwners(r.Context(), accountID, refresh)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var zones []string
	for _, it := range items {
		if !seen[it.Zone] {
			seen[it.Zone] = true
			zones = append(zones, it.Zone)
		}
	}
	if zones == nil {
		zones = []string{}
	}
	if items == nil {
		items = []issuer.ZoneOwner{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"zones": zones, "items": items})
	return nil
}

func (s *Server) addZone(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Domain    string `json:"domain"`
		AccountID string `json:"account_id"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	zone, err := zoneParam(in.Domain)
	if err != nil {
		return err
	}
	in.AccountID = strings.TrimSpace(in.AccountID)
	if in.AccountID != "" && !store.ValidID(in.AccountID) {
		return fail(http.StatusBadRequest, "未找到可用的阿里云 DNS 账户")
	}
	acct, dns, err := s.Manager.AccountClient(r.Context(), in.AccountID)
	if err != nil {
		return fail(http.StatusBadRequest, "未找到可用的阿里云 DNS 账户")
	}
	ns, err := dns.AddDomain(r.Context(), zone)
	if err != nil {
		return err
	}
	_, _ = s.Manager.SyncAccountZones(r.Context(), acct)
	s.audit(r, "dns.zone_add", zone, acct.Name)
	writeJSON(w, http.StatusCreated, map[string]any{
		"domain":       zone,
		"nameservers":  ns,
		"account_id":   acct.ID,
		"account_name": acct.Name,
	})
	return nil
}

func (s *Server) records(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	zone, err := zoneParam(q.Get("zone"))
	if err != nil {
		return err
	}
	page := 1
	if p := q.Get("page"); p != "" {
		page, err = strconv.Atoi(p)
		if err != nil || page < 1 || page > 100000 {
			return fail(http.StatusBadRequest, "页码无效")
		}
	}
	query := alidns.RecordQuery{Zone: zone, Page: page, PageSize: pageSize}
	if t := strings.ToUpper(strings.TrimSpace(q.Get("type"))); t != "" {
		if !recordTypes[t] {
			return fail(http.StatusBadRequest, "记录类型无效")
		}
		query.TypeKey = t
	}
	if kw := strings.TrimSpace(q.Get("keyword")); kw != "" {
		if len(kw) > 128 {
			return fail(http.StatusBadRequest, "关键字过长")
		}
		query.Keyword = kw
	}
	acct, dns, err := s.dnsForZone(r.Context(), zone, q.Get("account_id"))
	if err != nil {
		return fail(http.StatusBadRequest, "请先配置阿里云 DNS 账户")
	}
	items, total, err := dns.Records(r.Context(), query)
	if err != nil {
		return err
	}
	type rec struct {
		ID       string `json:"id"`
		RR       string `json:"rr"`
		Type     string `json:"type"`
		Value    string `json:"value"`
		TTL      int64  `json:"ttl"`
		Priority int64  `json:"priority"`
		Line     string `json:"line"`
		Status   string `json:"status"`
		Remark   string `json:"remark"`
	}
	out := make([]rec, 0, len(items))
	for _, it := range items {
		out = append(out, rec{
			ID:       it.RecordID,
			RR:       it.RR,
			Type:     it.Type,
			Value:    it.Value,
			TTL:      it.TTL,
			Priority: it.Priority,
			Line:     it.Line,
			Status:   it.Status,
			Remark:   it.Remark,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"records":      out,
		"total":        total,
		"page":         page,
		"page_size":    pageSize,
		"zone":         zone,
		"account_id":   acct.ID,
		"account_name": acct.Name,
		"edition":      acct.Edition,
	})
	return nil
}

type recordBody struct {
	Zone      string `json:"zone"`
	AccountID string `json:"account_id"`
	RR        string `json:"rr"`
	Type      string `json:"type"`
	Value     string `json:"value"`
	TTL       *int64 `json:"ttl"`
	Priority  *int64 `json:"priority"`
	Remark    string `json:"remark"`
}

func controlChars(s string) bool {
	for _, c := range s {
		if c < 32 || c == 127 || unicode.IsControl(c) {
			return true
		}
	}
	return false
}

func validateDNSRemark(raw string) (string, error) {
	remark := strings.TrimSpace(raw)
	if controlChars(remark) {
		return "", fail(http.StatusBadRequest, "备注不能包含换行或控制字符")
	}
	if utf8.RuneCountInString(remark) > 100 {
		return "", fail(http.StatusBadRequest, "备注长度不能超过 100 个字符")
	}
	return remark, nil
}

func (b *recordBody) validate() (string, alidns.RecordInput, error) {
	zone, err := zoneParam(b.Zone)
	if err != nil {
		return "", alidns.RecordInput{}, err
	}
	b.RR = strings.TrimSpace(b.RR)
	b.Type = strings.ToUpper(strings.TrimSpace(b.Type))
	b.Value = strings.TrimSpace(b.Value)
	remark, err := validateDNSRemark(b.Remark)
	if err != nil {
		return "", alidns.RecordInput{}, err
	}
	b.Remark = remark

	if !recordTypes[b.Type] {
		return "", alidns.RecordInput{}, fail(http.StatusBadRequest, "不支持的记录类型")
	}
	switch b.Type {
	case "CNAME", "MX", "NS", "SRV":
		b.Value = strings.TrimSuffix(b.Value, ".")
	case "CAA":
		if fields := strings.Fields(b.Value); len(fields) == 3 {
			val := fields[2]
			if !(len(val) >= 2 && strings.HasPrefix(val, `"`) && strings.HasSuffix(val, `"`)) && !strings.Contains(val, `"`) {
				b.Value = fields[0] + " " + fields[1] + ` "` + val + `"`
			}
		}
	}

	in := alidns.RecordInput{RR: b.RR, Type: b.Type, Value: b.Value, TTL: 600}
	if b.RR == "" || len(b.RR) > 253 || strings.IndexFunc(b.RR, unicode.IsSpace) >= 0 || controlChars(b.RR) {
		return "", in, fail(http.StatusBadRequest, "主机记录无效（根域名请填 @）")
	}
	if b.Value == "" || controlChars(b.Value) {
		return "", in, fail(http.StatusBadRequest, "记录值不能为空且不能包含控制字符")
	}
	if b.Type == "TXT" {
		if len(b.Value) > 512 {
			return "", in, fail(http.StatusBadRequest, "TXT 记录值长度不能超过 512 字符")
		}
	} else if len(b.Value) > 4096 {
		return "", in, fail(http.StatusBadRequest, "记录值长度不能超过 4096 字符")
	}
	if b.Type == "A" || b.Type == "AAAA" {
		ip := net.ParseIP(b.Value)
		if ip == nil || (b.Type == "A") != (ip.To4() != nil) || strings.Contains(b.Value, "%") {
			v := "4"
			if b.Type == "AAAA" {
				v = "6"
			}
			return "", in, fail(http.StatusBadRequest, "%s 记录需要有效的 IPv%s 地址", b.Type, v)
		}
	}
	if b.TTL != nil {
		if *b.TTL < 1 || *b.TTL > 86400 {
			return "", in, fail(http.StatusBadRequest, "TTL 需在 1-86400 之间")
		}
		in.TTL = *b.TTL
	}
	if b.Type == "MX" {
		if b.Priority == nil || *b.Priority < 1 || *b.Priority > 50 {
			return "", in, fail(http.StatusBadRequest, "MX 优先级需在 1-50 之间")
		}
		in.Priority = *b.Priority
	}
	return zone, in, nil
}

func (s *Server) addRecord(w http.ResponseWriter, r *http.Request) error {
	var b recordBody
	if err := decode(w, r, &b); err != nil {
		return err
	}
	zone, in, err := b.validate()
	if err != nil {
		return err
	}
	in.Line = "default"
	_, dns, err := s.dnsForZone(r.Context(), zone, b.AccountID)
	if err != nil {
		return err
	}
	id, err := dns.AddRecord(r.Context(), zone, in)
	if err != nil {
		return err
	}
	if b.Remark != "" {
		if remErr := dns.UpdateRecordRemark(r.Context(), id, b.Remark); remErr != nil {
			s.audit(r, "dns.record_add", fmt.Sprintf("%s.%s", in.RR, zone),
				fmt.Sprintf("%s -> %s (id=%s, remark_failed)", in.Type, in.Value, id))
			return fail(http.StatusBadGateway, "解析记录已创建 (RecordId: %s)，但设置备注失败: %s", id, alidns.Hint(remErr))
		}
	}
	s.audit(r, "dns.record_add", fmt.Sprintf("%s.%s", in.RR, zone), fmt.Sprintf("%s -> %s", in.Type, in.Value))
	writeJSON(w, http.StatusCreated, map[string]string{"id": id})
	return nil
}

func (s *Server) owned(ctx context.Context, dns *alidns.Client, id, zone string) (*alidns.Record, error) {
	if !recordIDRE.MatchString(id) {
		return nil, fail(http.StatusBadRequest, "记录 ID 无效")
	}
	info, err := dns.RecordInfo(ctx, id)
	if err != nil {
		return nil, err
	}
	owner, err := domain.Normalize(info.DomainName, false)
	if err != nil || info.RecordID != id {
		return nil, fail(http.StatusBadGateway, "阿里云返回的记录信息不完整，请刷新后重试")
	}
	if owner != zone {
		return nil, fail(http.StatusNotFound, "该记录不属于所选域名")
	}
	return info, nil
}

func (s *Server) updateRecord(w http.ResponseWriter, r *http.Request) error {
	var b recordBody
	if err := decode(w, r, &b); err != nil {
		return err
	}
	zone, in, err := b.validate()
	if err != nil {
		return err
	}
	_, dns, err := s.dnsForZone(r.Context(), zone, b.AccountID)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	info, err := s.owned(r.Context(), dns, id, zone)
	if err != nil {
		return err
	}

	recordChanged := in.RR != info.RR ||
		!strings.EqualFold(in.Type, info.Type) ||
		in.Value != info.Value ||
		in.TTL != info.TTL ||
		(in.Type == "MX" && in.Priority != info.Priority)

	if recordChanged {
		in.Line = info.Line
		if err := dns.UpdateRecord(r.Context(), id, in); err != nil {
			return err
		}
	}
	if b.Remark != info.Remark {
		if err := dns.UpdateRecordRemark(r.Context(), id, b.Remark); err != nil {
			return err
		}
	}
	s.audit(r, "dns.record_update", fmt.Sprintf("%s.%s", in.RR, zone), fmt.Sprintf("%s -> %s", in.Type, in.Value))
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
	return nil
}

func (s *Server) toggleRecordStatus(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Zone      string `json:"zone"`
		AccountID string `json:"account_id"`
		Enabled   bool   `json:"enabled"`
	}
	if err := decode(w, r, &b); err != nil {
		return err
	}
	zone, err := zoneParam(b.Zone)
	if err != nil {
		return err
	}
	_, dns, err := s.dnsForZone(r.Context(), zone, b.AccountID)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	info, err := s.owned(r.Context(), dns, id, zone)
	if err != nil {
		return err
	}
	if err := dns.SetRecordStatus(r.Context(), id, b.Enabled); err != nil {
		return err
	}
	s.audit(r, "dns.record_status", fmt.Sprintf("%s.%s", info.RR, zone), fmt.Sprintf("enabled=%v", b.Enabled))
	writeJSON(w, http.StatusOK, map[string]any{"id": id, "enabled": b.Enabled})
	return nil
}

func (s *Server) updateRecordRemark(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Zone      string `json:"zone"`
		AccountID string `json:"account_id"`
		Remark    string `json:"remark"`
	}
	if err := decode(w, r, &b); err != nil {
		return err
	}
	zone, err := zoneParam(b.Zone)
	if err != nil {
		return err
	}
	remark, err := validateDNSRemark(b.Remark)
	if err != nil {
		return err
	}
	_, dns, err := s.dnsForZone(r.Context(), zone, b.AccountID)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	info, err := s.owned(r.Context(), dns, id, zone)
	if err != nil {
		return err
	}
	if err := dns.UpdateRecordRemark(r.Context(), id, remark); err != nil {
		return err
	}
	s.audit(r, "dns.record_remark", fmt.Sprintf("%s.%s", info.RR, zone), remark)
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
	return nil
}

func (s *Server) deleteRecord(w http.ResponseWriter, r *http.Request) error {
	var b struct {
		Zone      string `json:"zone"`
		AccountID string `json:"account_id"`
	}
	if err := decode(w, r, &b); err != nil {
		return err
	}
	zone, err := zoneParam(b.Zone)
	if err != nil {
		return err
	}
	_, dns, err := s.dnsForZone(r.Context(), zone, b.AccountID)
	if err != nil {
		return err
	}
	id := r.PathValue("id")
	info, err := s.owned(r.Context(), dns, id, zone)
	if err != nil {
		return err
	}
	if err := dns.DeleteRecord(r.Context(), id); err != nil {
		return err
	}
	s.audit(r, "dns.record_delete", fmt.Sprintf("%s.%s", info.RR, zone), fmt.Sprintf("%s -> %s", info.Type, info.Value))
	writeJSON(w, http.StatusOK, map[string]string{"id": id})
	return nil
}

func formatZoneTXT(val string) string {
	raw := val
	if len(raw) >= 2 && strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) && !strings.Contains(raw[1:len(raw)-1], `"`) {
		raw = raw[1 : len(raw)-1]
	}
	escapeChunk := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		return `"` + s + `"`
	}
	if len(raw) <= 255 {
		return escapeChunk(raw)
	}
	var parts []string
	for len(raw) > 0 {
		n := 255
		if n >= len(raw) {
			n = len(raw)
		} else {
			for n > 0 && !utf8.RuneStart(raw[n]) {
				n--
			}
			if n == 0 {
				n = 255
			}
		}
		parts = append(parts, escapeChunk(raw[:n]))
		raw = raw[n:]
	}
	return strings.Join(parts, " ")
}

func sanitizeZoneComment(s string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
}

func (s *Server) exportZone(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	zone, err := zoneParam(q.Get("zone"))
	if err != nil {
		return err
	}
	_, dns, err := s.dnsForZone(r.Context(), zone, q.Get("account_id"))
	if err != nil {
		return err
	}
	records, err := dns.AllRecords(r.Context(), alidns.RecordQuery{Zone: zone})
	if err != nil {
		return err
	}
	var buf strings.Builder
	fmt.Fprintf(&buf, "; BIND zone export for %s\n; Exported at %s\n$ORIGIN %s.\n$TTL 600\n\n",
		zone, time.Now().UTC().Format(time.RFC3339), zone)
	for _, rec := range records {
		val := rec.Value
		recType := strings.ToUpper(strings.TrimSpace(rec.Type))
		switch recType {
		case "TXT":
			val = formatZoneTXT(val)
		case "CNAME", "MX", "NS", "SRV":
			if !strings.HasSuffix(val, ".") {
				val += "."
			}
		}
		if recType == "MX" {
			fmt.Fprintf(&buf, "%-24s %6d IN %-6s %d %s", rec.RR, rec.TTL, recType, rec.Priority, val)
		} else {
			fmt.Fprintf(&buf, "%-24s %6d IN %-6s %s", rec.RR, rec.TTL, recType, val)
		}
		if rec.Remark != "" {
			fmt.Fprintf(&buf, " ; %s", sanitizeZoneComment(rec.Remark))
		}
		buf.WriteByte('\n')
	}
	s.audit(r, "dns.export", zone, fmt.Sprintf("records=%d", len(records)))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s.zone"`, zone))
	_, _ = w.Write([]byte(buf.String()))
	return nil
}
