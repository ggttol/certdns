package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"

	"certdns/internal/alidns"
)

// DNSAccount represents a configured Alibaba Cloud DNS account.
type DNSAccount struct {
	ID              string   `json:"id"`
	Name            string   `json:"name"`
	Edition         string   `json:"edition"`   // "cn", "intl", "custom"
	RegionID        string   `json:"region_id"` // e.g. "cn-hangzhou", "ap-southeast-1"
	Endpoint        string   `json:"endpoint"`
	AccessKeyID     string   `json:"access_key_id"`
	MaskedKeyID     string   `json:"masked_key_id"`
	AccessKeySecret string   `json:"-"`
	Email           string   `json:"email"`
	IsDefault       bool     `json:"is_default"`
	Enabled         bool     `json:"enabled"`
	CachedZones     []string `json:"cached_zones"`
	LastCheckedAt   string   `json:"last_checked_at"`
	LastError       string   `json:"last_error"`
	CreatedAt       string   `json:"created_at"`
	UpdatedAt       string   `json:"updated_at"`
}

// Credentials returns alidns client credentials for this account.
func (a *DNSAccount) Credentials() alidns.Credentials {
	return alidns.Credentials{
		KeyID:    a.AccessKeyID,
		Secret:   a.AccessKeySecret,
		Edition:  a.Edition,
		RegionID: a.RegionID,
		Endpoint: a.Endpoint,
	}
}

const acctCols = `id,name,edition,region_id,endpoint,access_key_id,access_key_secret,email,is_default,enabled,
	cached_zones,COALESCE(last_checked_at,''),COALESCE(last_error,''),created_at,updated_at`

func (s *Store) scanDNSAccount(row interface{ Scan(...any) error }) (*DNSAccount, error) {
	var a DNSAccount
	var rawSecret, zonesJSON string
	if err := row.Scan(&a.ID, &a.Name, &a.Edition, &a.RegionID, &a.Endpoint, &a.AccessKeyID, &rawSecret,
		&a.Email, &a.IsDefault, &a.Enabled, &zonesJSON, &a.LastCheckedAt, &a.LastError, &a.CreatedAt, &a.UpdatedAt); err != nil {
		return nil, err
	}
	plainSecret, err := s.cipher.Open(rawSecret, aadDNSAccountSecret)
	if err != nil {
		return nil, err
	}
	a.AccessKeySecret = plainSecret
	a.MaskedKeyID = alidns.MaskKey(a.AccessKeyID)
	_ = json.Unmarshal([]byte(zonesJSON), &a.CachedZones)
	if a.CachedZones == nil {
		a.CachedZones = []string{}
	}
	return &a, nil
}

// DNSAccounts lists all DNS accounts with decrypted secrets.
func (s *Store) DNSAccounts(ctx context.Context) ([]*DNSAccount, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+acctCols+` FROM dns_accounts ORDER BY is_default DESC, created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*DNSAccount{}
	for rows.Next() {
		a, err := s.scanDNSAccount(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DNSAccount returns a single DNS account by ID.
func (s *Store) DNSAccount(ctx context.Context, id string) (*DNSAccount, error) {
	a, err := s.scanDNSAccount(s.db.QueryRowContext(ctx, `SELECT `+acctCols+` FROM dns_accounts WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// DefaultDNSAccount returns the preferred enabled DNS account.
func (s *Store) DefaultDNSAccount(ctx context.Context) (*DNSAccount, error) {
	a, err := s.scanDNSAccount(s.db.QueryRowContext(ctx, `SELECT `+acctCols+` FROM dns_accounts WHERE enabled=1 ORDER BY is_default DESC, created_at ASC LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return a, err
}

// CreateDNSAccount creates a DNS account, encrypting AccessKeySecret when a cipher is configured.
func (s *Store) CreateDNSAccount(ctx context.Context, a *DNSAccount) (*DNSAccount, error) {
	storedSecret := a.AccessKeySecret
	if s.cipher != nil {
		var err error
		storedSecret, err = s.cipher.Seal(a.AccessKeySecret, aadDNSAccountSecret)
		if err != nil {
			return nil, err
		}
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	if a.ID == "" {
		a.ID = NewID()
	}
	a.Edition, a.Endpoint, a.RegionID = alidns.ResolveEndpoint(a.Edition, a.Endpoint, a.RegionID)
	var count int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM dns_accounts`).Scan(&count); err != nil {
		return nil, err
	}
	if count == 0 {
		a.IsDefault = true
	}
	if a.IsDefault {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_accounts SET is_default=0`); err != nil {
			return nil, err
		}
	}
	zonesJSON, _ := json.Marshal(a.CachedZones)
	if len(zonesJSON) == 0 || string(zonesJSON) == "null" {
		zonesJSON = []byte("[]")
	}
	now := Now()
	a.CreatedAt, a.UpdatedAt = now, now
	_, err = tx.ExecContext(ctx, `INSERT INTO dns_accounts(id,name,edition,region_id,endpoint,access_key_id,access_key_secret,
		email,is_default,enabled,cached_zones,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		a.ID, strings.TrimSpace(a.Name), a.Edition, a.RegionID, a.Endpoint, a.AccessKeyID, storedSecret,
		a.Email, a.IsDefault, a.Enabled, string(zonesJSON), a.CreatedAt, a.UpdatedAt)
	if isUnique(err) {
		return nil, ErrDuplicate
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.DNSAccount(ctx, a.ID)
}

// UpdateDNSAccount updates an account. If in.AccessKeySecret is empty, the existing stored secret is preserved verbatim.
func (s *Store) UpdateDNSAccount(ctx context.Context, id string, in *DNSAccount) (*DNSAccount, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()

	var storedSecret string
	err = tx.QueryRowContext(ctx, `SELECT access_key_secret FROM dns_accounts WHERE id=?`, id).Scan(&storedSecret)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}

	if in.AccessKeySecret != "" {
		storedSecret = in.AccessKeySecret
		if s.cipher != nil {
			storedSecret, err = s.cipher.Seal(in.AccessKeySecret, aadDNSAccountSecret)
			if err != nil {
				return nil, err
			}
		}
	}

	ed, ep, reg := alidns.ResolveEndpoint(in.Edition, in.Endpoint, in.RegionID)
	if in.IsDefault {
		if _, err := tx.ExecContext(ctx, `UPDATE dns_accounts SET is_default=0 WHERE id<>?`, id); err != nil {
			return nil, err
		}
	}
	now := Now()
	_, err = tx.ExecContext(ctx, `UPDATE dns_accounts SET name=?,edition=?,region_id=?,endpoint=?,access_key_id=?,
		access_key_secret=?,email=?,is_default=?,enabled=?,updated_at=? WHERE id=?`,
		strings.TrimSpace(in.Name), ed, reg, ep, in.AccessKeyID, storedSecret, in.Email, in.IsDefault, in.Enabled, now, id)
	if isUnique(err) {
		return nil, ErrDuplicate
	}
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return s.DNSAccount(ctx, id)
}

// DeleteDNSAccount deletes an account, clears references on certificates and challenges,
// and promotes a remaining account to default if needed.
func (s *Store) DeleteDNSAccount(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	res, err := tx.ExecContext(ctx, `DELETE FROM dns_accounts WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET account_id='' WHERE account_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE challenges SET account_id='' WHERE account_id=?`, id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE dns_accounts SET is_default=1 WHERE id=(
		SELECT id FROM dns_accounts WHERE NOT EXISTS(SELECT 1 FROM dns_accounts WHERE is_default=1)
		ORDER BY created_at ASC LIMIT 1)`); err != nil {
		return err
	}
	return tx.Commit()
}

// SaveDNSAccountCheck records zone sync results or error status for a DNS account.
func (s *Store) SaveDNSAccountCheck(ctx context.Context, id string, zones []string, checkErr string) error {
	if zones == nil {
		zones = []string{}
	}
	raw, _ := json.Marshal(zones)
	now := Now()
	if checkErr == "" {
		_, err := s.db.ExecContext(ctx, `UPDATE dns_accounts SET cached_zones=?,last_checked_at=?,last_error=NULL,updated_at=? WHERE id=?`,
			string(raw), now, now, id)
		return err
	}
	_, err := s.db.ExecContext(ctx, `UPDATE dns_accounts SET last_checked_at=?,last_error=?,updated_at=? WHERE id=?`,
		now, checkErr, now, id)
	return err
}
