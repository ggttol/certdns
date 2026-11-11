// Package domain validates and normalizes DNS names.
package domain

import (
	"errors"
	"net"
	"regexp"
	"strings"

	"golang.org/x/net/idna"
)

var labelRE = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// Normalize lower-cases, punycodes and validates a hostname. When wildcard is
// true a single leading "*." label is accepted.
func Normalize(value string, wildcard bool) (string, error) {
	if value == "" || value != strings.TrimSpace(value) {
		return "", errors.New("域名不能为空或包含首尾空格")
	}
	value = strings.TrimSuffix(strings.ToLower(value), ".")
	prefix := ""
	if wildcard && strings.HasPrefix(value, "*.") {
		prefix, value = "*.", value[2:]
	}
	ascii, err := idna.Lookup.ToASCII(value)
	if err != nil {
		return "", errors.New("域名格式无效: " + value)
	}
	if net.ParseIP(ascii) != nil {
		return "", errors.New("不支持 IP 地址")
	}
	labels := strings.Split(ascii, ".")
	if len(ascii) > 253 || len(labels) < 2 {
		return "", errors.New("请使用完整域名: " + value)
	}
	for _, label := range labels {
		if !labelRE.MatchString(label) {
			return "", errors.New("域名格式无效: " + value)
		}
	}
	return prefix + ascii, nil
}

// MatchZone returns the longest managed zone that contains name.
func MatchZone(name string, zones []string) (string, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.TrimSuffix(strings.TrimPrefix(name, "*."), ".")
	if name == "" {
		return "", false
	}
	best := ""
	for _, raw := range zones {
		zone := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if zone == "" || len(zone) <= len(best) {
			continue
		}
		if name == zone || (len(name) > len(zone)+1 && name[len(name)-len(zone)-1] == '.' && strings.HasSuffix(name, zone)) {
			best = zone
		}
	}
	return best, best != ""
}

// Covers reports whether a certificate SAN (possibly wildcard) covers host.
func Covers(san, host string) bool {
	san = strings.ToLower(strings.TrimSpace(san))
	host = strings.ToLower(strings.TrimSpace(host))
	if san == "" || host == "" {
		return false
	}
	if san == host {
		return true
	}
	if strings.HasPrefix(san, "*.") {
		base := san[2:]
		if base == "" || len(host) <= len(base)+1 {
			return false
		}
		if host[len(host)-len(base)-1] != '.' || !strings.HasSuffix(host, base) {
			return false
		}
		rest := host[:len(host)-len(base)-1]
		return rest != "" && !strings.Contains(rest, ".") && !strings.Contains(rest, "*")
	}
	return false
}

// MatchScore scores how well sans match target:
//   - 2 for an exact case-insensitive SAN match (checked across all SANs first)
//   - 1 for a single-level wildcard SAN match when allowWildcard is true and target is not a wildcard
//   - 0 otherwise
func MatchScore(sans []string, target string, allowWildcard bool) int {
	t := strings.ToLower(strings.TrimSpace(target))
	if t == "" {
		return 0
	}
	for _, san := range sans {
		if strings.EqualFold(strings.TrimSpace(san), t) {
			return 2
		}
	}
	if allowWildcard && !strings.HasPrefix(t, "*.") {
		for _, san := range sans {
			s := strings.ToLower(strings.TrimSpace(san))
			if strings.HasPrefix(s, "*.") && Covers(s, t) {
				return 1
			}
		}
	}
	return 0
}
