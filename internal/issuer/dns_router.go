package issuer

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"certdns/internal/alidns"
	"certdns/internal/domain"
	"certdns/internal/store"
)

// ZoneOwner associates a DNS zone with the Alibaba Cloud account that hosts it.
type ZoneOwner struct {
	Zone        string `json:"zone"`
	AccountID   string `json:"account_id"`
	AccountName string `json:"account_name"`
	Edition     string `json:"edition"`
}

type zoneNotManagedError struct {
	domain string
}

func (e zoneNotManagedError) Error() string {
	return fmt.Sprintf("域名 %s 不在已配置的阿里云 DNS 托管列表中", e.domain)
}

// AccountClient returns the DNSAccount and Client for a specific account ID (or default if empty).
func (m *Manager) AccountClient(ctx context.Context, accountID string) (*store.DNSAccount, *alidns.Client, error) {
	var acct *store.DNSAccount
	var err error
	if accountID != "" {
		acct, err = m.Store.DNSAccount(ctx, accountID)
	} else {
		acct, err = m.Store.DefaultDNSAccount(ctx)
	}
	if err != nil {
		return nil, nil, err
	}
	return acct, m.NewDNS(acct.Credentials()), nil
}

// SyncAccountZones fetches live zones from AliDNS for an account and caches them in SQLite.
func (m *Manager) SyncAccountZones(ctx context.Context, acct *store.DNSAccount) ([]string, error) {
	client := m.NewDNS(acct.Credentials())
	zones, err := client.Zones(ctx)
	if err != nil {
		_ = m.Store.SaveDNSAccountCheck(ctx, acct.ID, nil, alidns.Hint(err))
		return nil, err
	}
	_ = m.Store.SaveDNSAccountCheck(ctx, acct.ID, zones, "")
	acct.CachedZones = zones
	return zones, nil
}

// ListZoneOwners returns all zones across enabled accounts (or a single account).
// When refresh is true or an account has never been checked, it queries AliDNS live.
func (m *Manager) ListZoneOwners(ctx context.Context, accountID string, refresh bool) ([]ZoneOwner, error) {
	accounts, err := m.Store.DNSAccounts(ctx)
	if err != nil {
		return nil, err
	}
	var out []ZoneOwner
	var firstErr error
	for _, a := range accounts {
		if !a.Enabled && a.ID != accountID {
			continue
		}
		if accountID != "" && a.ID != accountID {
			continue
		}
		zones := a.CachedZones
		if refresh || a.LastCheckedAt == "" {
			live, err := m.SyncAccountZones(ctx, a)
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				// Fall back to cached zones if available.
			} else {
				zones = live
			}
		}
		for _, z := range zones {
			out = append(out, ZoneOwner{
				Zone:        z,
				AccountID:   a.ID,
				AccountName: a.Name,
				Edition:     a.Edition,
			})
		}
	}
	if len(out) == 0 && firstErr != nil {
		return nil, firstErr
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Zone != out[j].Zone {
			return out[i].Zone < out[j].Zone
		}
		return out[i].AccountName < out[j].AccountName
	})
	return out, nil
}

// MatchDomainAccount finds the longest matching hosted zone and its owning DNSAccount for domainName.
func (m *Manager) MatchDomainAccount(ctx context.Context, domainName, preferredAccountID string, refresh bool) (*store.DNSAccount, *alidns.Client, string, error) {
	owners, err := m.ListZoneOwners(ctx, preferredAccountID, refresh)
	if err != nil && (preferredAccountID != "" || refresh) {
		return nil, nil, "", err
	}

	zones := make([]string, len(owners))
	for i, o := range owners {
		zones[i] = o.Zone
	}
	matchedZone, ok := domain.MatchZone(domainName, zones)
	if !ok && !refresh {
		return m.MatchDomainAccount(ctx, domainName, preferredAccountID, true)
	}
	if !ok {
		return nil, nil, "", zoneNotManagedError{domain: domainName}
	}

	bestAcctID := ""
	bestZone := matchedZone
	for _, o := range owners {
		if strings.EqualFold(strings.TrimSuffix(strings.TrimSpace(o.Zone), "."), matchedZone) {
			bestAcctID = o.AccountID
			bestZone = o.Zone
			break
		}
	}
	acct, client, err := m.AccountClient(ctx, bestAcctID)
	if err != nil {
		return nil, nil, "", err
	}
	return acct, client, bestZone, nil
}
