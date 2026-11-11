package store

import (
	"context"
	"database/sql"
	"errors"
)

// Setting returns the value for key, or "" if not present.
// When key is "webhook_url", encrypted values are transparently decrypted.
func (s *Store) Setting(ctx context.Context, key string) (string, error) {
	var v string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if key == "webhook_url" {
		return s.cipher.Open(v, aadWebhookURL)
	}
	return v, nil
}

// SetSettings atomically upserts key-value pairs in settings.
// When key is "webhook_url" and a cipher is configured, the value is encrypted at rest.
func (s *Store) SetSettings(ctx context.Context, kv map[string]string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for k, v := range kv {
		if k == "webhook_url" && s.cipher != nil {
			v, err = s.cipher.Seal(v, aadWebhookURL)
			if err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO settings(key,value) VALUES(?,?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value`, k, v); err != nil {
			return err
		}
	}
	return tx.Commit()
}
