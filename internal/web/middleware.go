package web

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"

	"certdns/internal/store"
)

const (
	secureSessionCookie   = "__Host-certdns_session"
	insecureSessionCookie = "certdns_session"
)

func (s *Server) cookieName() string {
	if s.InsecureCookie {
		return insecureSessionCookie
	}
	return secureSessionCookie
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   !s.InsecureCookie,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(sessionTTL.Seconds()),
	})
}

func (s *Server) clearSessionCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName(),
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !s.InsecureCookie,
		SameSite: http.SameSiteStrictMode,
	})
}

type authCtx struct {
	user *store.User
	csrf string
}

type ctxKey struct{}

func currentAuth(r *http.Request) *authCtx {
	a, _ := r.Context().Value(ctxKey{}).(*authCtx)
	return a
}

func currentUser(r *http.Request) *store.User {
	if a := currentAuth(r); a != nil {
		return a.user
	}
	return nil
}

func userRole(r *http.Request) string {
	if u := currentUser(r); u != nil {
		return u.Role
	}
	return ""
}

func (s *Server) auth(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		if sfs := strings.ToLower(strings.TrimSpace(r.Header.Get("Sec-Fetch-Site"))); sfs != "" && sfs != "same-origin" && sfs != "none" {
			return fail(http.StatusForbidden, "跨站请求已被拦截")
		}

		public := r.URL.Path == "/api/session" || r.URL.Path == "/api/login"
		token := ""
		if c, err := r.Cookie(s.cookieName()); err == nil {
			token = c.Value
		}

		var (
			u    *store.User
			csrf string
			ok   bool
		)
		if token != "" {
			u, csrf, ok = s.Store.SessionInfo(r.Context(), token)
		}

		if !public {
			if !ok || u == nil {
				return fail(http.StatusUnauthorized, "请先登录")
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				got := r.Header.Get("X-CSRF-Token")
				if got == "" || csrf == "" || subtle.ConstantTimeCompare([]byte(got), []byte(csrf)) != 1 {
					return fail(http.StatusForbidden, "CSRF 校验失败，请刷新页面")
				}
			}
		}

		if ok && u != nil {
			r = r.WithContext(context.WithValue(r.Context(), ctxKey{}, &authCtx{user: u, csrf: csrf}))
		}
		return h(w, r)
	}
}

func (s *Server) adminOnly(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		u := currentUser(r)
		if u == nil || u.Role != "admin" {
			return fail(http.StatusForbidden, "需要系统管理员权限")
		}
		return h(w, r)
	}
}

func (s *Server) operatorUp(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		u := currentUser(r)
		if u == nil || (u.Role != "admin" && u.Role != "operator") {
			return fail(http.StatusForbidden, "当前账号为只读权限，无法执行此操作")
		}
		return h(w, r)
	}
}

type tokenCtxKey struct{}

func currentAPIToken(r *http.Request) *store.APIToken {
	t, _ := r.Context().Value(tokenCtxKey{}).(*store.APIToken)
	return t
}

func extractBearerToken(r *http.Request) string {
	if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
		if len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
			return strings.TrimSpace(auth[7:])
		}
	}
	if tok := strings.TrimSpace(r.Header.Get("X-API-Token")); tok != "" {
		return tok
	}
	return ""
}

func (s *Server) tokenAuth(h handler) handler {
	return func(w http.ResponseWriter, r *http.Request) error {
		plain := extractBearerToken(r)
		if plain == "" {
			return fail(http.StatusUnauthorized, "缺少 API Token（请使用 Authorization: Bearer <token> 请求头）")
		}
		tok, ok := s.Store.AuthenticateAPIToken(r.Context(), plain, clientIP(r))
		if !ok || tok == nil {
			return fail(http.StatusUnauthorized, "API Token 无效或已被禁用")
		}
		r = r.WithContext(context.WithValue(r.Context(), tokenCtxKey{}, tok))
		return h(w, r)
	}
}

func (s *Server) audit(r *http.Request, action, target, detail string) {
	username := "anonymous"
	if u := currentUser(r); u != nil {
		username = u.Username
	}
	s.Store.AddAudit(r.Context(), username, clientIP(r), action, target, detail)
}
