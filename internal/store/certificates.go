package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
)

// Certificate represents a managed ACME or uploaded TLS certificate record.
type Certificate struct {
	ID        string   `json:"id"`
	Domains   []string `json:"domains"`
	Staging   bool     `json:"staging"`
	Status    string   `json:"status"`
	AutoRenew bool     `json:"auto_renew"`
	AccountID string   `json:"account_id"`
	KeyType   string   `json:"key_type"`
	Source    string   `json:"source"`
	Remark    string   `json:"remark"`
	SHA256    string   `json:"sha256,omitempty"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	Issuer    string   `json:"issuer"`
	LastError string   `json:"last_error"`
	CreatedAt string   `json:"created_at"`
	UpdatedAt string   `json:"updated_at"`
}

const certCols = `id,domains,staging,status,auto_renew,COALESCE(account_id,''),COALESCE(key_type,'EC256'),
	COALESCE(source,'acme'),COALESCE(remark,''),COALESCE(sha256,''),COALESCE(not_before,''),COALESCE(not_after,''),
	COALESCE(issuer,''),COALESCE(last_error,''),created_at,updated_at`

func scanCert(row interface{ Scan(...any) error }) (*Certificate, error) {
	var c Certificate
	var domains string
	if err := row.Scan(&c.ID, &domains, &c.Staging, &c.Status, &c.AutoRenew, &c.AccountID, &c.KeyType,
		&c.Source, &c.Remark, &c.SHA256, &c.NotBefore, &c.NotAfter, &c.Issuer, &c.LastError, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, err
	}
	if err := json.Unmarshal([]byte(domains), &c.Domains); err != nil {
		return nil, err
	}
	return &c, nil
}

// Certificates returns all certificates ordered newest-first.
func (s *Store) Certificates(ctx context.Context) ([]*Certificate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+certCols+` FROM certificates ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Certificate{}
	for rows.Next() {
		c, err := scanCert(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Certificate returns a single certificate by ID.
func (s *Store) Certificate(ctx context.Context, id string) (*Certificate, error) {
	c, err := scanCert(s.db.QueryRowContext(ctx, `SELECT `+certCols+` FROM certificates WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return c, err
}

// InsertCertificate stores a certificate row with the given status (used by custom upload).
func (s *Store) InsertCertificate(ctx context.Context, c *Certificate) error {
	if c.ID == "" {
		c.ID = NewID()
	}
	domains, _ := json.Marshal(c.Domains)
	if c.CreatedAt == "" {
		c.CreatedAt = Now()
	}
	if c.KeyType == "" {
		c.KeyType = "EC256"
	}
	if c.Source == "" {
		c.Source = "acme"
	}
	c.UpdatedAt = Now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO certificates(id,domains,staging,status,auto_renew,account_id,key_type,
		source,remark,sha256,not_before,not_after,issuer,last_error,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, string(domains), c.Staging, c.Status, c.AutoRenew, c.AccountID, c.KeyType, c.Source, c.Remark, c.SHA256,
		nullable(c.NotBefore), nullable(c.NotAfter), nullable(c.Issuer), nullable(c.LastError), c.CreatedAt, c.UpdatedAt)
	if isUnique(err) {
		return ErrDuplicate
	}
	return err
}

// CreateCertificateWithJob inserts a new certificate and queues its initial issue job atomically.
func (s *Store) CreateCertificateWithJob(ctx context.Context, c *Certificate) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	if c.ID == "" {
		c.ID = NewID()
	}
	domains, _ := json.Marshal(c.Domains)
	if c.KeyType == "" {
		c.KeyType = "EC256"
	}
	if c.Source == "" {
		c.Source = "acme"
	}
	now := Now()
	_, err = tx.ExecContext(ctx, `INSERT INTO certificates(id,domains,staging,status,auto_renew,account_id,key_type,source,remark,sha256,created_at,updated_at)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		c.ID, string(domains), c.Staging, "queued", c.AutoRenew, c.AccountID, c.KeyType, c.Source, c.Remark, c.SHA256, now, now)
	if isUnique(err) {
		return "", ErrDuplicate
	}
	if err != nil {
		return "", err
	}
	jobID, err := queueJob(ctx, tx, c.ID, "issue", "manual")
	if err != nil {
		return "", err
	}
	return jobID, tx.Commit()
}

// UpdateCertificateMeta updates mutable metadata fields on a certificate.
func (s *Store) UpdateCertificateMeta(ctx context.Context, id string, autoRenew *bool, accountID, remark *string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	cur, err := scanCert(tx.QueryRowContext(ctx, `SELECT `+certCols+` FROM certificates WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	if autoRenew != nil {
		cur.AutoRenew = *autoRenew
	}
	if accountID != nil {
		cur.AccountID = *accountID
	}
	if remark != nil {
		cur.Remark = *remark
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET auto_renew=?,account_id=?,remark=?,updated_at=? WHERE id=?`,
		cur.AutoRenew, cur.AccountID, cur.Remark, Now(), id); err != nil {
		return err
	}
	return tx.Commit()
}

// UpdateCertificateSHA256 updates the leaf DER SHA-256 fingerprint of a certificate.
func (s *Store) UpdateCertificateSHA256(ctx context.Context, id, sha256 string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE certificates SET sha256=? WHERE id=?`, sha256, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// HasActiveJob reports whether certID currently has a queued or running job.
func (s *Store) HasActiveJob(ctx context.Context, certID string) (bool, error) {
	var one int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM jobs WHERE certificate_id=? AND status IN ('queued','running')`, certID).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	return err == nil, err
}

// ActiveJobCertIDs returns the set of certificate IDs that currently have a queued or running job.
func (s *Store) ActiveJobCertIDs(ctx context.Context) (map[string]bool, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT DISTINCT certificate_id FROM jobs WHERE status IN ('queued','running')`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]bool)
	for rows.Next() {
		var certID string
		if err := rows.Scan(&certID); err != nil {
			return nil, err
		}
		out[certID] = true
	}
	return out, rows.Err()
}

// DeleteCertificate removes a certificate and its job history.
func (s *Store) DeleteCertificate(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE certificate_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM certificates WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
