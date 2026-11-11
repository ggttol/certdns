package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"

	"certdns/internal/domain"
)

// APIToken represents a scoped bearer token for remote certificate pulling.
type APIToken struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	TokenPrefix    string   `json:"token_prefix"`
	AllowedDomains []string `json:"allowed_domains"`
	Enabled        bool     `json:"enabled"`
	LastUsedAt     string   `json:"last_used_at,omitempty"`
	LastUsedIP     string   `json:"last_used_ip,omitempty"`
	CreatedAt      string   `json:"created_at"`
	UpdatedAt      string   `json:"updated_at"`
}

// AllowsDomain reports whether this token authorizes access to target under strict RFC 6125 semantics:
//   - "*" allows all non-empty targets;
//   - "*.example.com" allows "*.example.com" and single-label subdomains ("a.example.com"),
//     never the apex ("example.com") or multi-label subdomains ("a.b.example.com");
//   - "example.com" allows only "example.com" (never "*.example.com" or subdomains).
func (t *APIToken) AllowsDomain(target string) bool {
	if t == nil || !t.Enabled {
		return false
	}
	d := strings.ToLower(strings.TrimSpace(target))
	if d == "" {
		return false
	}
	for _, pat := range t.AllowedDomains {
		p := strings.ToLower(strings.TrimSpace(pat))
		if p == "" {
			continue
		}
		if p == "*" {
			return true
		}
		if strings.HasPrefix(p, "*.") {
			if len(p) > 2 && (d == p || (!strings.HasPrefix(d, "*.") && domain.Covers(p, d))) {
				return true
			}
			continue
		}
		if d == p {
			return true
		}
	}
	return false
}

// AllowsCertificate reports whether this token is authorized for EVERY SAN in domains.
func (t *APIToken) AllowsCertificate(domains []string) bool {
	if t == nil || !t.Enabled || len(domains) == 0 {
		return false
	}
	for _, d := range domains {
		if !t.AllowsDomain(d) {
			return false
		}
	}
	return true
}

func scanAPIToken(sc interface{ Scan(...any) error }) (*APIToken, error) {
	var t APIToken
	var rawDomains string
	var enabled int
	if err := sc.Scan(&t.ID, &t.Name, &t.TokenPrefix, &rawDomains, &enabled, &t.LastUsedAt, &t.LastUsedIP, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, err
	}
	t.Enabled = enabled != 0
	_ = json.Unmarshal([]byte(rawDomains), &t.AllowedDomains)
	if len(t.AllowedDomains) == 0 {
		t.AllowedDomains = []string{"*"}
	}
	return &t, nil
}

// APITokens lists all configured pull API tokens.
func (s *Store) APITokens(ctx context.Context) ([]*APIToken, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,name,token_prefix,COALESCE(allowed_domains,'["*"]'),enabled,COALESCE(last_used_at,''),COALESCE(last_used_ip,''),created_at,updated_at
		FROM api_tokens ORDER BY created_at ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*APIToken{}
	for rows.Next() {
		t, err := scanAPIToken(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// APIToken returns a pull API token by ID.
func (s *Store) APIToken(ctx context.Context, id string) (*APIToken, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id,name,token_prefix,COALESCE(allowed_domains,'["*"]'),enabled,COALESCE(last_used_at,''),COALESCE(last_used_ip,''),created_at,updated_at
		FROM api_tokens WHERE id=?`, id)
	t, err := scanAPIToken(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

// CreateAPIToken generates a new random API token ("cdns_<48hex>"), stores its SHA-256 hash,
// and returns both the metadata and the one-time plaintext token.
func (s *Store) CreateAPIToken(ctx context.Context, name string, allowedDomains []string) (*APIToken, string, error) {
	var b [24]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, "", err
	}
	plain := "cdns_" + hex.EncodeToString(b[:])
	return s.CreateAPITokenWithSecret(ctx, name, plain, allowedDomains)
}

// CreateAPITokenWithSecret creates an API token using a caller-supplied plaintext secret.
func (s *Store) CreateAPITokenWithSecret(ctx context.Context, name, plain string, allowedDomains []string) (*APIToken, string, error) {
	name = strings.TrimSpace(name)
	if len(allowedDomains) == 0 {
		allowedDomains = []string{"*"}
	}
	rawDomains, _ := json.Marshal(allowedDomains)
	prefix := plain
	if len(prefix) > 13 {
		prefix = prefix[:13] + "••••"
	}
	id := NewID()
	now := Now()
	_, err := s.db.ExecContext(ctx, `INSERT INTO api_tokens(id,name,token_prefix,token_hash,allowed_domains,enabled,created_at,updated_at)
		VALUES(?,?,?,?,?,1,?,?)`, id, name, prefix, hashToken(plain), string(rawDomains), now, now)
	if err != nil {
		if isUnique(err) {
			return nil, "", ErrDuplicate
		}
		return nil, "", err
	}
	tok, err := s.APIToken(ctx, id)
	return tok, plain, err
}

// UpdateAPIToken updates an API token's name, allowed domains, and enabled state.
func (s *Store) UpdateAPIToken(ctx context.Context, id, name string, allowedDomains []string, enabled bool) (*APIToken, error) {
	if len(allowedDomains) == 0 {
		allowedDomains = []string{"*"}
	}
	rawDomains, _ := json.Marshal(allowedDomains)
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	res, err := s.db.ExecContext(ctx, `UPDATE api_tokens SET name=?,allowed_domains=?,enabled=?,updated_at=? WHERE id=?`,
		strings.TrimSpace(name), string(rawDomains), enabledInt, Now(), id)
	if err != nil {
		if isUnique(err) {
			return nil, ErrDuplicate
		}
		return nil, err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return nil, ErrNotFound
	}
	return s.APIToken(ctx, id)
}

// DeleteAPIToken deletes an API token by ID.
func (s *Store) DeleteAPIToken(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM api_tokens WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// AuthenticateAPIToken verifies a bearer/header API token, updates last_used_at/ip, and returns the token record.
func (s *Store) AuthenticateAPIToken(ctx context.Context, plain, ip string) (*APIToken, bool) {
	plain = strings.TrimSpace(plain)
	if plain == "" {
		return nil, false
	}
	row := s.db.QueryRowContext(ctx, `SELECT id,name,token_prefix,COALESCE(allowed_domains,'["*"]'),enabled,COALESCE(last_used_at,''),COALESCE(last_used_ip,''),created_at,updated_at
		FROM api_tokens WHERE token_hash=?`, hashToken(plain))
	t, err := scanAPIToken(row)
	if err != nil || !t.Enabled {
		return nil, false
	}
	now := Now()
	_, _ = s.db.ExecContext(ctx, `UPDATE api_tokens SET last_used_at=?,last_used_ip=? WHERE id=?`, now, ip, t.ID)
	t.LastUsedAt = now
	t.LastUsedIP = ip
	return t, true
}
