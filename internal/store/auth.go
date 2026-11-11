package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func randomToken() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("store: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// CreateUserSession creates a session bound to an authenticated user.
func (s *Store) CreateUserSession(ctx context.Context, u *User, ip, ua string, ttl time.Duration) (token, csrf string, err error) {
	token, csrf = randomToken(), randomToken()
	now := time.Now()
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at < ?`, now.Unix())
	_, err = s.db.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,username,csrf,ip,user_agent,created_at,expires_at)
		VALUES(?,?,?,?,?,?,?,?)`, hashToken(token), u.ID, u.Username, csrf, ip, ua, Now(), now.Add(ttl).Unix())
	return token, csrf, err
}

// SessionInfo returns the authenticated active user and CSRF token for a valid session.
// Expired, orphaned, deleted-user, or disabled-user sessions are removed immediately.
func (s *Store) SessionInfo(ctx context.Context, token string) (*User, string, bool) {
	if token == "" {
		return nil, "", false
	}
	tokHash := hashToken(token)
	var (
		userID    string
		csrf      string
		expiresAt int64
	)
	err := s.db.QueryRowContext(ctx, `SELECT COALESCE(user_id,''), csrf, expires_at FROM sessions WHERE token_hash=?`, tokHash).
		Scan(&userID, &csrf, &expiresAt)
	if err != nil {
		return nil, "", false
	}
	if expiresAt < time.Now().Unix() || userID == "" {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokHash)
		return nil, "", false
	}
	u, err := s.UserByID(ctx, userID)
	if err != nil || !u.Enabled {
		_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokHash)
		return nil, "", false
	}
	return u, csrf, true
}

// DeleteSession deletes a session by raw token.
func (s *Store) DeleteSession(ctx context.Context, token string) {
	if token == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, hashToken(token))
}

// CheckLoginAllowed prunes expired login failures and reports whether ip has fewer than limit failures in window.
func (s *Store) CheckLoginAllowed(ctx context.Context, ip string, limit int, window time.Duration) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	cutoff := time.Now().Add(-window).Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_attempts WHERE at < ?`, cutoff); err != nil {
		return false, err
	}
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM login_attempts WHERE ip = ?`, ip).Scan(&count); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return count < limit, nil
}

// RecordLoginFailure prunes expired login failures and records a failed attempt for ip.
func (s *Store) RecordLoginFailure(ctx context.Context, ip string, window time.Duration) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	now := time.Now()
	cutoff := now.Add(-window).Unix()
	if _, err := tx.ExecContext(ctx, `DELETE FROM login_attempts WHERE at < ?`, cutoff); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO login_attempts(ip, at) VALUES(?, ?)`, ip, now.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

// ClearLoginFailures removes recorded login failures for ip after a successful login.
func (s *Store) ClearLoginFailures(ctx context.Context, ip string) {
	_, _ = s.db.ExecContext(ctx, `DELETE FROM login_attempts WHERE ip = ?`, ip)
}
