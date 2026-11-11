// Package store persists application state in SQLite.
package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"certdns/internal/secretbox"

	_ "modernc.org/sqlite"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrActiveJob = errors.New("active job exists")
	ErrDuplicate = errors.New("duplicate")
	ErrLastAdmin = errors.New("cannot remove or disable the last administrator")
)

const (
	aadDNSAccountSecret = "dns_accounts.access_key_secret"
	aadWebhookURL       = "settings.webhook_url"
)

// Store wraps the SQLite database and optional credential cipher.
type Store struct {
	db     *sql.DB
	cipher *secretbox.Cipher
}

const schema = `
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS users (
	id TEXT PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	display_name TEXT NOT NULL DEFAULT '',
	password_hash TEXT NOT NULL,
	role TEXT NOT NULL DEFAULT 'admin',
	enabled INTEGER NOT NULL DEFAULT 1,
	last_login_at TEXT,
	last_login_ip TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS dns_accounts (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	edition TEXT NOT NULL DEFAULT 'cn',
	region_id TEXT NOT NULL DEFAULT 'cn-hangzhou',
	endpoint TEXT NOT NULL DEFAULT 'https://alidns.aliyuncs.com/',
	access_key_id TEXT NOT NULL,
	access_key_secret TEXT NOT NULL,
	email TEXT NOT NULL DEFAULT '',
	is_default INTEGER NOT NULL DEFAULT 0,
	enabled INTEGER NOT NULL DEFAULT 1,
	cached_zones TEXT NOT NULL DEFAULT '[]',
	last_checked_at TEXT,
	last_error TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS certificates (
	id TEXT PRIMARY KEY,
	domains TEXT NOT NULL,
	staging INTEGER NOT NULL DEFAULT 0,
	status TEXT NOT NULL,
	auto_renew INTEGER NOT NULL DEFAULT 1,
	account_id TEXT NOT NULL DEFAULT '',
	key_type TEXT NOT NULL DEFAULT 'EC256',
	source TEXT NOT NULL DEFAULT 'acme',
	remark TEXT NOT NULL DEFAULT '',
	sha256 TEXT NOT NULL DEFAULT '',
	not_before TEXT,
	not_after TEXT,
	issuer TEXT,
	last_error TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS certificates_domainset ON certificates(domains, staging);

CREATE TABLE IF NOT EXISTS jobs (
	id TEXT PRIMARY KEY,
	certificate_id TEXT NOT NULL,
	kind TEXT NOT NULL,
	status TEXT NOT NULL,
	trigger TEXT NOT NULL DEFAULT 'manual',
	created_at TEXT NOT NULL,
	started_at TEXT,
	finished_at TEXT,
	output TEXT NOT NULL DEFAULT '');
CREATE UNIQUE INDEX IF NOT EXISTS jobs_one_active ON jobs(certificate_id) WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS jobs_created ON jobs(created_at);

CREATE TABLE IF NOT EXISTS challenges (
	record_id TEXT PRIMARY KEY,
	certificate_id TEXT NOT NULL,
	account_id TEXT NOT NULL DEFAULT '',
	zone TEXT NOT NULL,
	rr TEXT NOT NULL,
	value TEXT NOT NULL,
	created_at TEXT NOT NULL);

CREATE TABLE IF NOT EXISTS sessions (
	token_hash TEXT PRIMARY KEY,
	user_id TEXT NOT NULL DEFAULT '',
	username TEXT NOT NULL DEFAULT 'admin',
	csrf TEXT NOT NULL,
	ip TEXT NOT NULL DEFAULT '',
	user_agent TEXT NOT NULL DEFAULT '',
	created_at TEXT NOT NULL DEFAULT '',
	expires_at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS login_attempts (ip TEXT NOT NULL, at INTEGER NOT NULL);

CREATE TABLE IF NOT EXISTS audit_logs (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	created_at TEXT NOT NULL,
	username TEXT NOT NULL,
	ip TEXT NOT NULL,
	action TEXT NOT NULL,
	target TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT '');
CREATE INDEX IF NOT EXISTS audit_logs_created ON audit_logs(id DESC);

CREATE TABLE IF NOT EXISTS api_tokens (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	token_prefix TEXT NOT NULL,
	token_hash TEXT NOT NULL UNIQUE,
	allowed_domains TEXT NOT NULL DEFAULT '["*"]',
	enabled INTEGER NOT NULL DEFAULT 1,
	last_used_at TEXT,
	last_used_ip TEXT,
	created_at TEXT NOT NULL,
	updated_at TEXT NOT NULL);
`

// Open opens or initializes the SQLite database at path with hardened permissions,
// schema migrations, and at-rest credential encryption.
func Open(path string, cipher *secretbox.Cipher) (*Store, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}
	if err := tightenSQLiteFilePerms(path); err != nil {
		return nil, err
	}

	dsn := "file:" + path + "?_pragma=busy_timeout(10000)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=secure_delete(ON)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)

	if _, err := db.Exec(schema); err != nil {
		_ = db.Close()
		return nil, err
	}

	s := &Store{db: db, cipher: cipher}
	ctx := context.Background()
	if err := s.migrateSchema(ctx); err != nil {
		_ = db.Close()
		return nil, err
	}
	dirty, err := s.migrateData(ctx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	if dirty {
		if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if cipher != nil {
		if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			_ = db.Close()
			return nil, err
		}
	}
	if err := tightenSQLiteFilePerms(path); err != nil {
		_ = db.Close()
		return nil, err
	}
	return s, nil
}

func tightenSQLiteFilePerms(path string) error {
	if err := os.Chmod(path, 0o600); err != nil {
		return err
	}
	for _, suffix := range []string{"-wal", "-shm"} {
		if err := os.Chmod(path+suffix, 0o600); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}

type colMigration struct {
	name string
	ddl  string
}

func (s *Store) migrateSchema(ctx context.Context) error {
	tableMigrations := []struct {
		table string
		cols  []colMigration
	}{
		{
			table: "certificates",
			cols: []colMigration{
				{name: "account_id", ddl: `ALTER TABLE certificates ADD COLUMN account_id TEXT NOT NULL DEFAULT ''`},
				{name: "key_type", ddl: `ALTER TABLE certificates ADD COLUMN key_type TEXT NOT NULL DEFAULT 'EC256'`},
				{name: "source", ddl: `ALTER TABLE certificates ADD COLUMN source TEXT NOT NULL DEFAULT 'acme'`},
				{name: "remark", ddl: `ALTER TABLE certificates ADD COLUMN remark TEXT NOT NULL DEFAULT ''`},
				{name: "sha256", ddl: `ALTER TABLE certificates ADD COLUMN sha256 TEXT NOT NULL DEFAULT ''`},
			},
		},
		{
			table: "challenges",
			cols: []colMigration{
				{name: "account_id", ddl: `ALTER TABLE challenges ADD COLUMN account_id TEXT NOT NULL DEFAULT ''`},
			},
		},
		{
			table: "sessions",
			cols: []colMigration{
				{name: "user_id", ddl: `ALTER TABLE sessions ADD COLUMN user_id TEXT NOT NULL DEFAULT ''`},
				{name: "username", ddl: `ALTER TABLE sessions ADD COLUMN username TEXT NOT NULL DEFAULT 'admin'`},
				{name: "ip", ddl: `ALTER TABLE sessions ADD COLUMN ip TEXT NOT NULL DEFAULT ''`},
				{name: "user_agent", ddl: `ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT ''`},
				{name: "created_at", ddl: `ALTER TABLE sessions ADD COLUMN created_at TEXT NOT NULL DEFAULT ''`},
			},
		},
	}

	for _, tm := range tableMigrations {
		existing, err := tableColumns(ctx, s.db, tm.table)
		if err != nil {
			return err
		}
		for _, col := range tm.cols {
			if !existing[col.name] {
				if _, err := s.db.ExecContext(ctx, col.ddl); err != nil {
					return err
				}
			}
		}
	}

	loginCols, err := tableColumns(ctx, s.db, "login_attempts")
	if err != nil {
		return err
	}
	if !loginCols["ip"] {
		if _, err := s.db.ExecContext(ctx, `DROP TABLE login_attempts`); err != nil {
			return err
		}
		if _, err := s.db.ExecContext(ctx, `CREATE TABLE login_attempts (ip TEXT NOT NULL, at INTEGER NOT NULL)`); err != nil {
			return err
		}
	}
	if _, err := s.db.ExecContext(ctx, `CREATE INDEX IF NOT EXISTS login_attempts_ip_at ON login_attempts(ip, at)`); err != nil {
		return err
	}
	return nil
}

func tableColumns(ctx context.Context, db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.QueryContext(ctx, "PRAGMA table_info("+table+")")
	if err != nil {
		return nil, err
	}
	cols := make(map[string]bool)
	for rows.Next() {
		var (
			cid       int
			name      string
			colType   string
			notNull   int
			dfltValue sql.NullString
			pk        int
		)
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dfltValue, &pk); err != nil {
			_ = rows.Close()
			return nil, err
		}
		cols[strings.ToLower(name)] = true
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return cols, nil
}

func (s *Store) migrateData(ctx context.Context) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	dirty := false

	var hasUsers bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users)`).Scan(&hasUsers); err != nil {
		return false, err
	}
	if hasUsers {
		res, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key='password_hash'`)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			dirty = true
		}
	}

	var hasAccounts bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM dns_accounts)`).Scan(&hasAccounts); err != nil {
		return false, err
	}
	if hasAccounts {
		res, err := tx.ExecContext(ctx, `DELETE FROM settings WHERE key IN ('alidns_key_id','alidns_secret')`)
		if err != nil {
			return false, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			dirty = true
		}
	}

	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=''`); err != nil {
		return false, err
	}

	if s.cipher != nil {
		type acctSecret struct {
			id     string
			secret string
		}
		rows, err := tx.QueryContext(ctx, `SELECT id, access_key_secret FROM dns_accounts`)
		if err != nil {
			return false, err
		}
		var accts []acctSecret
		for rows.Next() {
			var item acctSecret
			if err := rows.Scan(&item.id, &item.secret); err != nil {
				_ = rows.Close()
				return false, err
			}
			accts = append(accts, item)
		}
		if err := rows.Close(); err != nil {
			return false, err
		}
		if err := rows.Err(); err != nil {
			return false, err
		}

		for _, item := range accts {
			if item.secret == "" {
				continue
			}
			if strings.HasPrefix(item.secret, secretbox.Prefix) {
				if _, err := s.cipher.Open(item.secret, aadDNSAccountSecret); err != nil {
					return false, fmt.Errorf("store: decrypt dns_accounts(%s) failed: %w", item.id, err)
				}
				continue
			}
			sealed, err := s.cipher.Seal(item.secret, aadDNSAccountSecret)
			if err != nil {
				return false, err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE dns_accounts SET access_key_secret=? WHERE id=?`, sealed, item.id); err != nil {
				return false, err
			}
			dirty = true
		}

		var webhookVal string
		err = tx.QueryRowContext(ctx, `SELECT value FROM settings WHERE key='webhook_url'`).Scan(&webhookVal)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		if err == nil && webhookVal != "" {
			if strings.HasPrefix(webhookVal, secretbox.Prefix) {
				if _, err := s.cipher.Open(webhookVal, aadWebhookURL); err != nil {
					return false, fmt.Errorf("store: decrypt settings(webhook_url) failed: %w", err)
				}
			} else {
				sealed, err := s.cipher.Seal(webhookVal, aadWebhookURL)
				if err != nil {
					return false, err
				}
				if _, err := tx.ExecContext(ctx, `UPDATE settings SET value=? WHERE key='webhook_url'`, sealed); err != nil {
					return false, err
				}
				dirty = true
			}
		}
	}

	if err := tx.Commit(); err != nil {
		return false, err
	}
	return dirty, nil
}

// Close closes the underlying SQLite connection pool.
func (s *Store) Close() error { return s.db.Close() }

// ValidID reports whether id is a 32-character lowercase hexadecimal identifier.
func ValidID(id string) bool {
	if len(id) != 32 {
		return false
	}
	for i := range 32 {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

// Now returns the current UTC timestamp formatted as RFC3339.
func Now() string { return time.Now().UTC().Format(time.RFC3339) }

// NewID generates a random 16-byte lowercase hex identifier.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("store: crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

func isUnique(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}

func nullable(v string) any {
	if v == "" {
		return nil
	}
	return v
}
