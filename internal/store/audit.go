package store

import (
	"context"
	"strings"
)

// AuditLog records a security or operational event.
type AuditLog struct {
	ID        int64  `json:"id"`
	CreatedAt string `json:"created_at"`
	Username  string `json:"username"`
	IP        string `json:"ip"`
	Action    string `json:"action"`
	Target    string `json:"target"`
	Detail    string `json:"detail"`
}

// AuditFilter specifies optional prefix and keyword filters for querying audit logs.
type AuditFilter struct {
	Action  string
	Keyword string
	Limit   int
}

var likeEscaper = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

// AddAudit appends an audit entry and bounds the audit table to the latest 2000 rows.
func (s *Store) AddAudit(ctx context.Context, username, ip, action, target, detail string) {
	_, _ = s.db.ExecContext(ctx, `INSERT INTO audit_logs(created_at,username,ip,action,target,detail) VALUES(?,?,?,?,?,?)`,
		Now(), username, ip, action, target, detail)
	_, _ = s.db.ExecContext(ctx, `DELETE FROM audit_logs WHERE id <= (SELECT MAX(id)-2000 FROM audit_logs)`)
}

// AuditLogs queries audit entries matching f ordered newest-first (default limit 200, max 500).
func (s *Store) AuditLogs(ctx context.Context, f AuditFilter) ([]AuditLog, error) {
	limit := f.Limit
	if limit <= 0 {
		limit = 200
	} else if limit > 500 {
		limit = 500
	}

	var (
		conds []string
		args  []any
	)
	if action := strings.TrimSpace(f.Action); action != "" {
		conds = append(conds, `action LIKE ? ESCAPE '\'`)
		args = append(args, likeEscaper.Replace(action)+"%")
	}
	if kw := strings.TrimSpace(f.Keyword); kw != "" {
		pat := "%" + likeEscaper.Replace(kw) + "%"
		conds = append(conds, `(username LIKE ? ESCAPE '\' OR target LIKE ? ESCAPE '\' OR detail LIKE ? ESCAPE '\' OR ip LIKE ? ESCAPE '\')`)
		args = append(args, pat, pat, pat, pat)
	}

	query := `SELECT id,created_at,username,ip,action,target,detail FROM audit_logs`
	if len(conds) > 0 {
		query += ` WHERE ` + strings.Join(conds, ` AND `)
	}
	query += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)

	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []AuditLog{}
	for rows.Next() {
		var a AuditLog
		if err := rows.Scan(&a.ID, &a.CreatedAt, &a.Username, &a.IP, &a.Action, &a.Target, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
