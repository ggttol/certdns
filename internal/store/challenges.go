package store

import "context"

// Challenge tracks a DNS-01 TXT record created during ACME validation.
type Challenge struct {
	RecordID, CertificateID, AccountID, Zone, RR, Value string
}

// AddChallenge records a live DNS-01 TXT record in the journal.
func (s *Store) AddChallenge(ctx context.Context, c Challenge) error {
	_, err := s.db.ExecContext(ctx, `INSERT OR REPLACE INTO challenges(record_id,certificate_id,account_id,zone,rr,value,created_at)
		VALUES(?,?,?,?,?,?,?)`, c.RecordID, c.CertificateID, c.AccountID, c.Zone, c.RR, c.Value, Now())
	return err
}

// RemoveChallenge deletes a cleaned-up DNS-01 TXT record from the journal.
func (s *Store) RemoveChallenge(ctx context.Context, recordID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM challenges WHERE record_id=?`, recordID)
	return err
}

// Challenges returns all pending DNS-01 TXT records in the journal.
func (s *Store) Challenges(ctx context.Context) ([]Challenge, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT record_id,certificate_id,COALESCE(account_id,''),zone,rr,value FROM challenges`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Challenge{}
	for rows.Next() {
		var c Challenge
		if err := rows.Scan(&c.RecordID, &c.CertificateID, &c.AccountID, &c.Zone, &c.RR, &c.Value); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
