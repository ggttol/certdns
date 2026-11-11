// Package web serves the management UI and JSON API.
package web

import (
	"bytes"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"certdns/internal/alidns"
	"certdns/internal/issuer"
	"certdns/internal/store"
)

//go:embed static
var staticFS embed.FS

const (
	sessionTTL   = 12 * time.Hour
	pageSize     = 100
	maxBodyBytes = 256 << 10
)

// Server serves the management console and REST/Pull APIs.
type Server struct {
	Store          *store.Store
	Manager        *issuer.Manager
	InsecureCookie bool

	loginOnce sync.Once
	loginSem  chan struct{}
}

func (s *Server) getLoginSem() chan struct{} {
	s.loginOnce.Do(func() {
		s.loginSem = make(chan struct{}, 4)
	})
	return s.loginSem
}

type apiError struct {
	status int
	msg    string
}

func (e *apiError) Error() string { return e.msg }

func fail(status int, format string, args ...any) error {
	return &apiError{status: status, msg: fmt.Sprintf(format, args...)}
}

type handler func(w http.ResponseWriter, r *http.Request) error

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	remoteAddr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	remoteAddr = remoteAddr.Unmap()
	if remoteAddr.IsLoopback() || remoteAddr.IsPrivate() {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if xffAddr, err := netip.ParseAddr(strings.TrimSpace(first)); err == nil && xffAddr.Zone() == "" {
				return xffAddr.Unmap().String()
			}
		}
	}
	return remoteAddr.String()
}

func (s *Server) wrap(h handler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		err := h(w, r)
		if err == nil {
			return
		}
		var ae *apiError
		var de *alidns.Error
		switch {
		case errors.As(err, &ae):
			writeJSON(w, ae.status, map[string]string{"error": ae.msg})
		case errors.As(err, &de):
			status := http.StatusBadGateway
			if de.Code != "" {
				status = http.StatusBadRequest
			}
			writeJSON(w, status, map[string]string{"error": alidns.Hint(err)})
		default:
			log.Printf("%s %s: %v", r.Method, r.URL.Path, err)
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "内部错误，请查看服务日志"})
		}
	}
}

func isJSONContentType(ct string) bool {
	mediaType, _, err := mime.ParseMediaType(ct)
	return err == nil && strings.EqualFold(mediaType, "application/json")
}

func decode(w http.ResponseWriter, r *http.Request, v any) error {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		return fail(http.StatusUnsupportedMediaType, "请求必须为 JSON")
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(v); err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fail(http.StatusRequestEntityTooLarge, "请求内容过大（上限 256 KB）")
		}
		return fail(http.StatusBadRequest, "请求格式无效")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fail(http.StatusRequestEntityTooLarge, "请求内容过大（上限 256 KB）")
		}
		return fail(http.StatusBadRequest, "请求格式无效")
	}
	return nil
}

func decodeOptional(w http.ResponseWriter, r *http.Request, v any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	data, err := io.ReadAll(r.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return fail(http.StatusRequestEntityTooLarge, "请求内容过大（上限 256 KB）")
		}
		return fail(http.StatusBadRequest, "请求格式无效")
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		return fail(http.StatusUnsupportedMediaType, "请求必须为 JSON")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(v); err != nil {
		return fail(http.StatusBadRequest, "请求格式无效")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return fail(http.StatusBadRequest, "请求格式无效")
	}
	return nil
}

// Handler builds the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(staticFS, "static")
	files := http.StripPrefix("/assets/", http.FileServer(http.FS(static)))
	mux.HandleFunc("GET /assets/", func(w http.ResponseWriter, r *http.Request) {
		rel := strings.TrimPrefix(r.URL.Path, "/assets/")
		if rel == "" ||
			rel == "index.html" ||
			strings.HasSuffix(rel, "/index.html") ||
			strings.Contains(rel, "..") ||
			strings.Contains(rel, "\\") ||
			strings.HasPrefix(rel, "/") ||
			(!strings.HasSuffix(rel, ".css") && !strings.HasSuffix(rel, ".js")) {
			http.NotFound(w, r)
			return
		}
		files.ServeHTTP(w, r)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		b, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "missing index.html", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(b)
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	api := map[string]handler{
		"GET /api/session":                    s.session,
		"POST /api/login":                     s.login,
		"POST /api/logout":                    s.logout,
		"POST /api/password":                  s.changePassword,
		"GET /api/users":                      s.adminOnly(s.listUsers),
		"POST /api/users":                     s.adminOnly(s.createUser),
		"PUT /api/users/{id}":                 s.adminOnly(s.updateUser),
		"DELETE /api/users/{id}":              s.adminOnly(s.deleteUser),
		"GET /api/accounts":                   s.listAccounts,
		"POST /api/accounts":                  s.adminOnly(s.createAccount),
		"PUT /api/accounts/{id}":              s.adminOnly(s.updateAccount),
		"DELETE /api/accounts/{id}":           s.adminOnly(s.deleteAccount),
		"POST /api/accounts/{id}/test":        s.operatorUp(s.testAccount),
		"POST /api/accounts/sync-all":         s.operatorUp(s.syncAllAccounts),
		"GET /api/settings":                   s.getSettings,
		"PUT /api/settings/webhook":           s.adminOnly(s.putWebhook),
		"POST /api/settings/webhook/test":     s.adminOnly(s.testWebhook),
		"GET /api/tokens":                     s.adminOnly(s.listAPITokens),
		"POST /api/tokens":                    s.adminOnly(s.createAPIToken),
		"PUT /api/tokens/{id}":                s.adminOnly(s.updateAPIToken),
		"DELETE /api/tokens/{id}":             s.adminOnly(s.deleteAPIToken),
		"GET /api/audit":                      s.adminOnly(s.listAudit),
		"GET /api/certificates":               s.listCertificates,
		"POST /api/certificates":              s.operatorUp(s.issue),
		"POST /api/certificates/upload":       s.operatorUp(s.uploadCertificate),
		"GET /api/certificates/{id}":          s.certificateDetail,
		"PUT /api/certificates/{id}":          s.operatorUp(s.updateCertificate),
		"POST /api/certificates/{id}/renew":   s.operatorUp(s.renew),
		"DELETE /api/certificates/{id}":       s.operatorUp(s.deleteCertificate),
		"GET /api/certificates/{id}/download": s.operatorUp(s.download),
		"GET /api/jobs":                       s.listJobs,
		"GET /api/jobs/{id}":                  s.job,
		"GET /api/dns/zones":                  s.zones,
		"POST /api/dns/zones":                 s.operatorUp(s.addZone),
		"GET /api/dns/records":                s.records,
		"POST /api/dns/records":               s.operatorUp(s.addRecord),
		"PUT /api/dns/records/{id}":           s.operatorUp(s.updateRecord),
		"POST /api/dns/records/{id}/status":   s.operatorUp(s.toggleRecordStatus),
		"PUT /api/dns/records/{id}/remark":    s.operatorUp(s.updateRecordRemark),
		"DELETE /api/dns/records/{id}":        s.operatorUp(s.deleteRecord),
		"GET /api/dns/export":                 s.exportZone,
	}
	for pattern, h := range api {
		mux.Handle(pattern, s.wrap(s.auth(h)))
	}
	mux.Handle("GET /api/v1/pull/certificates", s.wrap(s.tokenAuth(s.pullListCertificates)))
	mux.Handle("GET /api/v1/pull/certificates/{domain}", s.wrap(s.tokenAuth(s.pullCertificateByDomain)))
	mux.Handle("/api/", s.wrap(func(w http.ResponseWriter, r *http.Request) error {
		return fail(http.StatusNotFound, "接口不存在")
	}))
	return s.securityHeaders(mux)
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		if !s.InsecureCookie {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		h.Set("Cache-Control", "no-store")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		next.ServeHTTP(w, r)
	})
}
