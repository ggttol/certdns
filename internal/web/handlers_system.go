package web

import (
	"net/http"
	"strconv"
	"strings"

	"certdns/internal/store"
	"certdns/internal/webhook"
)

func (s *Server) getSettings(w http.ResponseWriter, r *http.Request) error {
	ctx := r.Context()
	accts, err := s.Store.DNSAccounts(ctx)
	if err != nil {
		return err
	}
	configured := false
	email := ""
	for _, a := range accts {
		if a.Enabled {
			configured = true
			if email == "" && a.Email != "" {
				email = a.Email
			}
		}
	}
	webhookURL, err := s.Store.Setting(ctx, "webhook_url")
	if err != nil {
		return err
	}
	webhookConfigured := strings.TrimSpace(webhookURL) != ""
	shownWebhook := ""
	if userRole(r) == "admin" {
		shownWebhook = webhookURL
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured":         configured,
		"email":              email,
		"hostname":           s.Manager.Hostname,
		"tls_cert_id":        s.Manager.TLSCertID(ctx),
		"webhook_configured": webhookConfigured,
		"webhook_url":        shownWebhook,
	})
	return nil
}

func (s *Server) putWebhook(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		WebhookURL string `json:"webhook_url"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	allowPrivate := s.Manager != nil && s.Manager.Webhook != nil && s.Manager.Webhook.AllowPrivate
	u, err := webhook.ValidateTarget(in.WebhookURL, allowPrivate)
	if err != nil {
		return fail(http.StatusBadRequest, "%s", err.Error())
	}
	if err := s.Store.SetSettings(r.Context(), map[string]string{"webhook_url": u}); err != nil {
		return err
	}
	s.audit(r, "webhook.update", webhook.MaskURL(u), "")
	writeJSON(w, http.StatusOK, map[string]any{
		"webhook_url":        u,
		"webhook_configured": u != "",
	})
	return nil
}

func (s *Server) testWebhook(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		WebhookURL *string `json:"webhook_url"`
	}
	if err := decodeOptional(w, r, &in); err != nil {
		return err
	}
	var rawURL string
	if in.WebhookURL != nil {
		rawURL = strings.TrimSpace(*in.WebhookURL)
		if rawURL == "" {
			return fail(http.StatusBadRequest, "请先填写 Webhook 地址")
		}
	} else {
		saved, err := s.Store.Setting(r.Context(), "webhook_url")
		if err != nil {
			return err
		}
		rawURL = strings.TrimSpace(saved)
		if rawURL == "" {
			return fail(http.StatusBadRequest, "请先填写并保存 Webhook 地址")
		}
	}

	var sender *webhook.Sender
	if s.Manager != nil && s.Manager.Webhook != nil {
		sender = s.Manager.Webhook
	} else {
		hostname := ""
		if s.Manager != nil {
			hostname = s.Manager.Hostname
		}
		sender = webhook.NewSender(hostname)
	}
	if err := sender.Send(r.Context(), rawURL, "测试通知", "这是一条来自 CertDNS 的连通性测试消息。"); err != nil {
		return fail(http.StatusBadRequest, "发送失败: %v", err)
	}
	s.audit(r, "webhook.test", webhook.MaskURL(rawURL), "")
	writeJSON(w, http.StatusOK, map[string]bool{"sent": true})
	return nil
}

func (s *Server) listAudit(w http.ResponseWriter, r *http.Request) error {
	q := r.URL.Query()
	limit := 200
	if rawLimit := strings.TrimSpace(q.Get("limit")); rawLimit != "" {
		n, err := strconv.Atoi(rawLimit)
		if err != nil || n < 1 {
			return fail(http.StatusBadRequest, "limit 参数无效")
		}
		limit = n
	}
	kw := strings.TrimSpace(q.Get("q"))
	if kw == "" {
		kw = strings.TrimSpace(q.Get("keyword"))
	}
	logs, err := s.Store.AuditLogs(r.Context(), store.AuditFilter{
		Action:  strings.TrimSpace(q.Get("action")),
		Keyword: kw,
		Limit:   limit,
	})
	if err != nil {
		return err
	}
	if logs == nil {
		logs = []store.AuditLog{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"logs": logs})
	return nil
}
