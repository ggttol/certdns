package store

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// User represents a console operator or administrator account.
type User struct {
	ID           string `json:"id"`
	Username     string `json:"username"`
	DisplayName  string `json:"display_name"`
	PasswordHash string `json:"-"`
	Role         string `json:"role"` // "admin", "operator", "viewer"
	Enabled      bool   `json:"enabled"`
	LastLoginAt  string `json:"last_login_at"`
	LastLoginIP  string `json:"last_login_ip"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
}

const userCols = `id,username,display_name,password_hash,role,enabled,COALESCE(last_login_at,''),COALESCE(last_login_ip,''),created_at,updated_at`

func scanUser(row interface{ Scan(...any) error }) (*User, error) {
	var u User
	err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, &u.Role, &u.Enabled, &u.LastLoginAt, &u.LastLoginIP, &u.CreatedAt, &u.UpdatedAt)
	return &u, err
}

// Users returns all console users ordered by creation time.
func (s *Store) Users(ctx context.Context) ([]*User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+userCols+` FROM users ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*User{}
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// UserByID looks up a user by ID.
func (s *Store) UserByID(ctx context.Context, id string) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// UserByUsername looks up a user case-insensitively by username.
func (s *Store) UserByUsername(ctx context.Context, username string) (*User, error) {
	u, err := scanUser(s.db.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE lower(username)=lower(?)`, username))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return u, err
}

// CreateUser inserts a new user record.
func (s *Store) CreateUser(ctx context.Context, u *User) (*User, error) {
	if u.ID == "" {
		u.ID = NewID()
	}
	now := Now()
	u.CreatedAt, u.UpdatedAt = now, now
	if u.Role == "" {
		u.Role = "operator"
	}
	u.Username = strings.ToLower(strings.TrimSpace(u.Username))
	u.DisplayName = strings.TrimSpace(u.DisplayName)
	_, err := s.db.ExecContext(ctx, `INSERT INTO users(id,username,display_name,password_hash,role,enabled,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?)`, u.ID, u.Username, u.DisplayName,
		u.PasswordHash, u.Role, u.Enabled, u.CreatedAt, u.UpdatedAt)
	if isUnique(err) {
		return nil, ErrDuplicate
	}
	return u, err
}

func (s *Store) countActiveAdmins(ctx context.Context, tx *sql.Tx, excludeID string) (int, error) {
	var n int
	err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM users WHERE role='admin' AND enabled=1 AND id<>?`, excludeID).Scan(&n)
	return n, err
}

// UpdateUser updates display name, role, enabled state, and optionally password hash.
func (s *Store) UpdateUser(ctx context.Context, id string, displayName, role string, enabled bool, newPasswordHash string) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	cur, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if (cur.Role == "admin" && role != "admin") || (cur.Role == "admin" && !enabled) {
		otherAdmins, err := s.countActiveAdmins(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		if otherAdmins == 0 {
			return nil, ErrLastAdmin
		}
	}
	pwHash := cur.PasswordHash
	if newPasswordHash != "" {
		pwHash = newPasswordHash
	}
	now := Now()
	if _, err := tx.ExecContext(ctx, `UPDATE users SET display_name=?,role=?,enabled=?,password_hash=?,updated_at=? WHERE id=?`,
		strings.TrimSpace(displayName), role, enabled, pwHash, now, id); err != nil {
		return nil, err
	}
	if !enabled || newPasswordHash != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.UserByID(ctx, id)
}

// DeleteUser deletes a user and revokes their active sessions, refusing to remove the last active admin.
func (s *Store) DeleteUser(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cur, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userCols+` FROM users WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if cur.Role == "admin" && cur.Enabled {
		otherAdmins, err := s.countActiveAdmins(ctx, tx, id)
		if err != nil {
			return err
		}
		if otherAdmins == 0 {
			return ErrLastAdmin
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM users WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}

// TouchUserLogin records the timestamp and client IP of a successful login.
func (s *Store) TouchUserLogin(ctx context.Context, id, ip string) {
	_, _ = s.db.ExecContext(ctx, `UPDATE users SET last_login_at=?,last_login_ip=? WHERE id=?`, Now(), ip, id)
}
