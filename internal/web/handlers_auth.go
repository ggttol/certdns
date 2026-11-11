package web

import (
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"certdns/internal/pwhash"
	"certdns/internal/store"
)

const (
	loginLimit        = 10
	loginWindow       = 15 * time.Minute
	dummyPasswordHash = "scrypt:32768:8:1$dummysalt1234567$00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
)

var (
	usernameRE = regexp.MustCompile(`^[a-zA-Z0-9_.-]{2,32}$`)
	validRoles = map[string]bool{"admin": true, "operator": true, "viewer": true}
)

func (s *Server) session(w http.ResponseWriter, r *http.Request) error {
	a := currentAuth(r)
	if a == nil {
		writeJSON(w, http.StatusOK, map[string]any{
			"authenticated": false,
			"csrf":          "",
			"hostname":      s.Manager.Hostname,
		})
		return nil
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"csrf":          a.csrf,
		"hostname":      s.Manager.Hostname,
		"user": map[string]any{
			"id":           a.user.ID,
			"username":     a.user.Username,
			"display_name": a.user.DisplayName,
			"role":         a.user.Role,
		},
	})
	return nil
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	if r.Header.Get("X-Requested-With") != "certdns" {
		return fail(http.StatusForbidden, "请求来源无效")
	}

	sem := s.getLoginSem()
	select {
	case sem <- struct{}{}:
		defer func() { <-sem }()
	case <-r.Context().Done():
		return r.Context().Err()
	}

	ctx := r.Context()
	ip := clientIP(r)
	username := strings.ToLower(strings.TrimSpace(in.Username))
	if username == "" {
		username = "admin"
	}

	allowed, err := s.Store.CheckLoginAllowed(ctx, ip, loginLimit, loginWindow)
	if err != nil {
		return err
	}
	if !allowed {
		return fail(http.StatusTooManyRequests, "登录尝试过多，请 15 分钟后再试")
	}

	u, err := s.Store.UserByUsername(ctx, username)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		return err
	}

	pwSample := in.Password
	if len(pwSample) > 1024 {
		pwSample = pwSample[:1024]
	}

	verified := false
	if err == nil && u != nil && u.Enabled && len(in.Password) <= 1024 {
		verified = pwhash.Verify(u.PasswordHash, in.Password)
	} else {
		_ = pwhash.Verify(dummyPasswordHash, pwSample)
	}

	if !verified {
		_ = s.Store.RecordLoginFailure(ctx, ip, loginWindow)
		s.Store.AddAudit(ctx, username, ip, "user.login_failed", username, "用户名或密码错误")
		return fail(http.StatusUnauthorized, "用户名或密码错误")
	}

	s.Store.ClearLoginFailures(ctx, ip)
	for _, ck := range r.Cookies() {
		if (ck.Name == secureSessionCookie || ck.Name == insecureSessionCookie) && ck.Value != "" {
			s.Store.DeleteSession(ctx, ck.Value)
		}
	}

	s.Store.TouchUserLogin(ctx, u.ID, ip)
	token, csrf, err := s.Store.CreateUserSession(ctx, u, ip, r.UserAgent(), sessionTTL)
	if err != nil {
		return err
	}
	s.Store.AddAudit(ctx, u.Username, ip, "user.login", u.Username, fmt.Sprintf("角色: %s", u.Role))
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{
		"authenticated": true,
		"csrf":          csrf,
		"hostname":      s.Manager.Hostname,
		"user": map[string]any{
			"id":           u.ID,
			"username":     u.Username,
			"display_name": u.DisplayName,
			"role":         u.Role,
		},
	})
	return nil
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) error {
	s.audit(r, "user.logout", "", "")
	if c, err := r.Cookie(s.cookieName()); err == nil && c.Value != "" {
		s.Store.DeleteSession(r.Context(), c.Value)
	}
	s.clearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{"authenticated": false})
	return nil
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Current string `json:"current"`
		New     string `json:"new"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	u := currentUser(r)
	if u == nil {
		return fail(http.StatusUnauthorized, "请先登录")
	}
	ctx := r.Context()
	fullUser, err := s.Store.UserByID(ctx, u.ID)
	if err != nil {
		return err
	}
	if !pwhash.Verify(fullUser.PasswordHash, in.Current) {
		return fail(http.StatusBadRequest, "当前密码错误")
	}
	if len(in.New) < 10 || len(in.New) > 256 {
		return fail(http.StatusBadRequest, "新密码长度需为 10-256 个字符")
	}
	newHash, err := pwhash.Hash(in.New)
	if err != nil {
		return err
	}
	if _, err := s.Store.UpdateUser(ctx, fullUser.ID, fullUser.DisplayName, fullUser.Role, fullUser.Enabled, newHash); err != nil {
		return err
	}
	if c, err := r.Cookie(s.cookieName()); err == nil && c.Value != "" {
		s.Store.DeleteSession(ctx, c.Value)
	}
	token, csrf, err := s.Store.CreateUserSession(ctx, fullUser, clientIP(r), r.UserAgent(), sessionTTL)
	if err != nil {
		return err
	}
	s.audit(r, "user.password_change", fullUser.Username, "修改个人密码")
	s.setSessionCookie(w, token)
	writeJSON(w, http.StatusOK, map[string]any{"changed": true, "csrf": csrf})
	return nil
}

func (s *Server) listUsers(w http.ResponseWriter, r *http.Request) error {
	users, err := s.Store.Users(r.Context())
	if err != nil {
		return err
	}
	if users == nil {
		users = []*store.User{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"users": users})
	return nil
}

func (s *Server) createUser(w http.ResponseWriter, r *http.Request) error {
	var in struct {
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Password    string `json:"password"`
		Role        string `json:"role"`
		Enabled     *bool  `json:"enabled"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	in.Username = strings.ToLower(strings.TrimSpace(in.Username))
	if !usernameRE.MatchString(in.Username) {
		return fail(http.StatusBadRequest, "用户名需为 2-32 位字母、数字、下划线或点号")
	}
	if len(in.Password) < 10 || len(in.Password) > 256 {
		return fail(http.StatusBadRequest, "密码长度需为 10-256 个字符")
	}
	if in.Role == "" {
		in.Role = "operator"
	}
	if !validRoles[in.Role] {
		return fail(http.StatusBadRequest, "角色无效（可选 admin / operator / viewer）")
	}
	hash, err := pwhash.Hash(in.Password)
	if err != nil {
		return err
	}
	enabled := in.Enabled == nil || *in.Enabled
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		displayName = in.Username
	}
	u, err := s.Store.CreateUser(r.Context(), &store.User{
		Username:     in.Username,
		DisplayName:  displayName,
		PasswordHash: hash,
		Role:         in.Role,
		Enabled:      enabled,
	})
	if errors.Is(err, store.ErrDuplicate) {
		return fail(http.StatusConflict, "用户名 %s 已存在", in.Username)
	}
	if err != nil {
		return err
	}
	s.audit(r, "user.create", u.Username, fmt.Sprintf("角色: %s", u.Role))
	writeJSON(w, http.StatusCreated, u)
	return nil
}

func (s *Server) updateUser(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return fail(http.StatusNotFound, "用户不存在")
	}
	var in struct {
		DisplayName string `json:"display_name"`
		Role        string `json:"role"`
		Enabled     *bool  `json:"enabled"`
		Password    string `json:"password"`
	}
	if err := decode(w, r, &in); err != nil {
		return err
	}
	cur, err := s.Store.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "用户不存在")
	}
	if err != nil {
		return err
	}
	me := currentUser(r)
	enabled := cur.Enabled
	if in.Enabled != nil {
		enabled = *in.Enabled
	}
	role := cur.Role
	if in.Role != "" {
		if !validRoles[in.Role] {
			return fail(http.StatusBadRequest, "角色无效")
		}
		role = in.Role
	}
	if me != nil && me.ID == id {
		if !enabled {
			return fail(http.StatusBadRequest, "不能禁用当前登录的账号")
		}
		if role != "admin" {
			return fail(http.StatusBadRequest, "不能降级当前登录的管理员账号")
		}
	}
	newHash := ""
	if in.Password != "" {
		if len(in.Password) < 10 || len(in.Password) > 256 {
			return fail(http.StatusBadRequest, "新密码长度需为 10-256 个字符")
		}
		newHash, err = pwhash.Hash(in.Password)
		if err != nil {
			return err
		}
	}
	displayName := strings.TrimSpace(in.DisplayName)
	if displayName == "" {
		displayName = cur.DisplayName
	}
	updated, err := s.Store.UpdateUser(r.Context(), id, displayName, role, enabled, newHash)
	if errors.Is(err, store.ErrLastAdmin) {
		return fail(http.StatusBadRequest, "系统至少需要保留一名启用状态的管理员")
	}
	if err != nil {
		return err
	}
	s.audit(r, "user.update", updated.Username, fmt.Sprintf("角色: %s, 启用: %v, 重置密码: %v", updated.Role, updated.Enabled, newHash != ""))
	writeJSON(w, http.StatusOK, updated)
	return nil
}

func (s *Server) deleteUser(w http.ResponseWriter, r *http.Request) error {
	id := r.PathValue("id")
	if !store.ValidID(id) {
		return fail(http.StatusNotFound, "用户不存在")
	}
	if me := currentUser(r); me != nil && me.ID == id {
		return fail(http.StatusBadRequest, "不能删除当前登录的账号")
	}
	target, err := s.Store.UserByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		return fail(http.StatusNotFound, "用户不存在")
	}
	if err != nil {
		return err
	}
	if err := s.Store.DeleteUser(r.Context(), id); err != nil {
		if errors.Is(err, store.ErrLastAdmin) {
			return fail(http.StatusBadRequest, "不能删除最后一名系统管理员")
		}
		return err
	}
	s.audit(r, "user.delete", target.Username, "")
	writeJSON(w, http.StatusOK, map[string]bool{"deleted": true})
	return nil
}
