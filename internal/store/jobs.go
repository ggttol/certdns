package store

import (
	"context"
	"database/sql"
	"errors"
)

// Job represents a queued, running, or completed ACME issuance/renewal task.
type Job struct {
	ID            string `json:"id"`
	CertificateID string `json:"certificate_id"`
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	Trigger       string `json:"trigger"`
	CreatedAt     string `json:"created_at"`
	StartedAt     string `json:"started_at"`
	FinishedAt    string `json:"finished_at"`
	Output        string `json:"output,omitempty"`
}

const jobCols = `id,certificate_id,kind,status,trigger,created_at,COALESCE(started_at,''),COALESCE(finished_at,''),output`

func scanJob(row interface{ Scan(...any) error }) (*Job, error) {
	var j Job
	err := row.Scan(&j.ID, &j.CertificateID, &j.Kind, &j.Status, &j.Trigger, &j.CreatedAt, &j.StartedAt, &j.FinishedAt, &j.Output)
	return &j, err
}

func queueJob(ctx context.Context, tx *sql.Tx, certID, kind, trigger string) (string, error) {
	id := NewID()
	now := Now()
	_, err := tx.ExecContext(ctx, `INSERT INTO jobs(id,certificate_id,kind,status,trigger,created_at)
		VALUES(?,?,?,?,?,?)`, id, certID, kind, "queued", trigger, now)
	if isUnique(err) {
		return "", ErrActiveJob
	}
	if err != nil {
		return "", err
	}
	_, err = tx.ExecContext(ctx, `UPDATE certificates SET status=CASE WHEN status='valid' THEN 'renewing' ELSE 'queued' END,
		updated_at=? WHERE id=?`, now, certID)
	return id, err
}

// QueueJob queues an issuance or renewal job for an existing certificate.
func (s *Store) QueueJob(ctx context.Context, certID, kind, trigger string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var one int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM certificates WHERE id=?`, certID).Scan(&one); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrNotFound
		}
		return "", err
	}
	id, err := queueJob(ctx, tx, certID, kind, trigger)
	if err != nil {
		return "", err
	}
	return id, tx.Commit()
}

// Jobs lists the most recent jobs without output bodies.
func (s *Store) Jobs(ctx context.Context, limit int) ([]*Job, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobCols+` FROM jobs ORDER BY created_at DESC, rowid DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []*Job{}
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			return nil, err
		}
		j.Output = ""
		out = append(out, j)
	}
	return out, rows.Err()
}

// Job returns a single job including its log output.
func (s *Store) Job(ctx context.Context, id string) (*Job, error) {
	j, err := scanJob(s.db.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return j, err
}

// ClaimJob marks the oldest queued job running and returns it (nil when idle).
func (s *Store) ClaimJob(ctx context.Context) (*Job, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	j, err := scanJob(tx.QueryRowContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE status='queued' ORDER BY created_at ASC, rowid ASC LIMIT 1`))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	now := Now()
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status='running',started_at=? WHERE id=?`, now, j.ID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET status=CASE WHEN status='renewing' THEN 'renewing' ELSE 'issuing' END,
		updated_at=? WHERE id=?`, now, j.CertificateID); err != nil {
		return nil, err
	}
	j.Status, j.StartedAt = "running", now
	return j, tx.Commit()
}

// AppendJobOutput appends log lines to a job's bounded output buffer.
func (s *Store) AppendJobOutput(ctx context.Context, id, text string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE jobs SET output=substr(output || ?, -32000) WHERE id=?`, text, id)
	return err
}

// IssuedInfo describes metadata of a freshly issued certificate.
type IssuedInfo struct {
	NotBefore, NotAfter, Issuer, SHA256 string
}

// FinishJob records the outcome on both the job and its certificate, and prunes
// completed job history beyond the newest 500 finished entries.
func (s *Store) FinishJob(ctx context.Context, job *Job, info *IssuedInfo, failure string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	now := Now()
	status := "succeeded"
	if info == nil {
		status = "failed"
	}
	if _, err := tx.ExecContext(ctx, `UPDATE jobs SET status=?,finished_at=?,
		output=substr(output || ?, -32000) WHERE id=?`, status, now, tail(failure), job.ID); err != nil {
		return err
	}
	if info != nil {
		_, err = tx.ExecContext(ctx, `UPDATE certificates SET status='valid',not_before=?,not_after=?,issuer=?,sha256=?,
			last_error=NULL,updated_at=? WHERE id=?`,
			info.NotBefore, info.NotAfter, info.Issuer, info.SHA256, now, job.CertificateID)
	} else {
		_, err = tx.ExecContext(ctx, `UPDATE certificates SET status=CASE WHEN not_after IS NOT NULL AND not_after > ? THEN 'valid' ELSE 'error' END,
			last_error=?,updated_at=? WHERE id=?`, now, failure, now, job.CertificateID)
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM jobs WHERE status IN ('succeeded','failed') AND id NOT IN (
		SELECT id FROM jobs WHERE status IN ('succeeded','failed') ORDER BY created_at DESC, rowid DESC LIMIT 500)`); err != nil {
		return err
	}
	return tx.Commit()
}

func tail(failure string) string {
	if failure == "" {
		return ""
	}
	return "\n[失败] " + failure + "\n"
}

// RequeueJob returns a running job back to queued state during graceful shutdown
// without marking the certificate as failed.
func (s *Store) RequeueJob(ctx context.Context, job *Job, note string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	extra := ""
	if note != "" {
		extra = "\n[提示] " + note + "\n"
	}
	res, err := tx.ExecContext(ctx, `UPDATE jobs SET status='queued',started_at=NULL,finished_at=NULL,
		output=substr(output || ?, -32000) WHERE id=?`, extra, job.ID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if _, err := tx.ExecContext(ctx, `UPDATE certificates SET status=CASE WHEN status='renewing' THEN 'renewing' ELSE 'queued' END,
		updated_at=? WHERE id=?`, Now(), job.CertificateID); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	job.Status = "queued"
	job.StartedAt = ""
	job.FinishedAt = ""
	return nil
}

// RecoverInterrupted fails jobs left running by an unclean crash.
func (s *Store) RecoverInterrupted(ctx context.Context) error {
	rows, err := s.db.QueryContext(ctx, `SELECT `+jobCols+` FROM jobs WHERE status='running'`)
	if err != nil {
		return err
	}
	var jobs []*Job
	for rows.Next() {
		j, err := scanJob(rows)
		if err != nil {
			_ = rows.Close()
			return err
		}
		jobs = append(jobs, j)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if err := rows.Err(); err != nil {
		return err
	}
	for _, j := range jobs {
		if err := s.FinishJob(ctx, j, nil, "服务重启导致任务中断，请重新执行"); err != nil {
			return err
		}
	}
	return nil
}
