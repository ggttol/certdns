package domain

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	t.Parallel()

	validCases := []struct {
		name     string
		input    string
		wildcard bool
		want     string
	}{
		{name: "mixed case", input: "Cert.Example.ORG", wildcard: false, want: "cert.example.org"},
		{name: "trailing dot", input: "Example.COM.", wildcard: false, want: "example.com"},
		{name: "hyphenated labels", input: "my-api-01.sub.example.com", wildcard: false, want: "my-api-01.sub.example.com"},
		{name: "punycode german", input: "München.de", wildcard: false, want: "xn--mnchen-3ya.de"},
		{name: "punycode chinese", input: "例.中国", wildcard: false, want: "xn--fsq.xn--fiqs8s"},
		{name: "wildcard allowed", input: "*.Example.ORG", wildcard: true, want: "*.example.org"},
		{name: "wildcard punycode", input: "*.München.de.", wildcard: true, want: "*.xn--mnchen-3ya.de"},
		{name: "exact when wildcard allowed", input: "cert.example.org", wildcard: true, want: "cert.example.org"},
	}

	for _, tc := range validCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Normalize(tc.input, tc.wildcard)
			if err != nil {
				t.Fatalf("Normalize(%q, %v) unexpected error: %v", tc.input, tc.wildcard, err)
			}
			if got != tc.want {
				t.Fatalf("Normalize(%q, %v) = %q, want %q", tc.input, tc.wildcard, got, tc.want)
			}
		})
	}

	longDomain := strings.Repeat("a.", 126) + "bc" // 254 chars

	invalidCases := []struct {
		name     string
		input    string
		wildcard bool
	}{
		{name: "empty", input: "", wildcard: false},
		{name: "leading space", input: " example.com", wildcard: false},
		{name: "trailing space", input: "example.com ", wildcard: false},
		{name: "tab whitespace", input: "\texample.com", wildcard: true},
		{name: "wildcard rejected when false", input: "*.example.com", wildcard: false},
		{name: "double wildcard", input: "*.*.example.com", wildcard: true},
		{name: "mid wildcard", input: "sub.*.example.com", wildcard: true},
		{name: "wildcard single label base", input: "*.com", wildcard: true},
		{name: "ipv4 literal", input: "127.0.0.1", wildcard: false},
		{name: "ipv4 metadata literal", input: "100.100.100.200", wildcard: true},
		{name: "ipv6 literal", input: "::1", wildcard: false},
		{name: "single label", input: "localhost", wildcard: false},
		{name: "single label trailing dot", input: "localhost.", wildcard: false},
		{name: "leading hyphen", input: "-bad.example.com", wildcard: false},
		{name: "trailing hyphen", input: "bad-.example.com", wildcard: false},
		{name: "empty middle label", input: "a..example.com", wildcard: false},
		{name: "over 253 chars", input: longDomain, wildcard: false},
	}

	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := Normalize(tc.input, tc.wildcard)
			if err == nil {
				t.Fatalf("Normalize(%q, %v) = %q, expected error", tc.input, tc.wildcard, got)
			}
		})
	}
}

func TestMatchZone(t *testing.T) {
	t.Parallel()

	zones := []string{"example.org", "sub.example.org", "example.com"}

	cases := []struct {
		name      string
		domain    string
		zones     []string
		wantZone  string
		wantMatch bool
	}{
		{name: "exact zone", domain: "example.org", zones: zones, wantZone: "example.org", wantMatch: true},
		{name: "single subdomain", domain: "cert.example.org", zones: zones, wantZone: "example.org", wantMatch: true},
		{name: "longest suffix match", domain: "api.sub.example.org", zones: zones, wantZone: "sub.example.org", wantMatch: true},
		{name: "longest suffix reverse order", domain: "api.sub.example.org", zones: []string{"sub.example.org", "example.org"}, wantZone: "sub.example.org", wantMatch: true},
		{name: "wildcard stripped", domain: "*.example.org", zones: zones, wantZone: "example.org", wantMatch: true},
		{name: "wildcard deeper zone", domain: "*.sub.example.org.", zones: zones, wantZone: "sub.example.org", wantMatch: true},
		{name: "mixed case domain and zones", domain: " *.Cert.Example.ORG. ", zones: []string{"EXAMPLE.ORG."}, wantZone: "example.org", wantMatch: true},
		{name: "label boundary mismatch", domain: "myexample.org", zones: zones, wantZone: "", wantMatch: false},
		{name: "unmanaged domain", domain: "other.org", zones: zones, wantZone: "", wantMatch: false},
		{name: "empty domain", domain: "", zones: zones, wantZone: "", wantMatch: false},
		{name: "bare wildcard", domain: "*.", zones: zones, wantZone: "", wantMatch: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotZone, gotMatch := MatchZone(tc.domain, tc.zones)
			if gotZone != tc.wantZone || gotMatch != tc.wantMatch {
				t.Fatalf("MatchZone(%q, %v) = (%q, %v), want (%q, %v)",
					tc.domain, tc.zones, gotZone, gotMatch, tc.wantZone, tc.wantMatch)
			}
		})
	}
}

func TestCovers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		san  string
		host string
		want bool
	}{
		{name: "exact lowercase", san: "cert.example.com", host: "cert.example.com", want: true},
		{name: "exact mixed case and whitespace", san: "  Cert.Example.COM ", host: "cert.example.com", want: true},
		{name: "wildcard exact match", san: "*.Example.COM", host: "*.example.com", want: true},
		{name: "single level wildcard", san: "*.example.com", host: "sub.example.com", want: true},
		{name: "single level wildcard mixed case", san: "*.Example.COM", host: "Sub.EXAMPLE.com", want: true},
		{name: "apex not covered by wildcard", san: "*.example.com", host: "example.com", want: false},
		{name: "multi level not covered by wildcard", san: "*.example.com", host: "a.b.example.com", want: false},
		{name: "sub wildcard not covered by wildcard", san: "*.example.com", host: "*.sub.example.com", want: false},
		{name: "suffix without dot boundary", san: "*.example.com", host: "badexample.com", want: false},
		{name: "sibling host mismatch", san: "cert.example.com", host: "api.example.com", want: false},
		{name: "empty inputs", san: "", host: "", want: false},
		{name: "malformed bare wildcard", san: "*.", host: "a.", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := Covers(tc.san, tc.host); got != tc.want {
				t.Fatalf("Covers(%q, %q) = %v, want %v", tc.san, tc.host, got, tc.want)
			}
		})
	}
}

func TestMatchScore(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name          string
		sans          []string
		target        string
		allowWildcard bool
		want          int
	}{
		{
			name:          "wildcard before exact still returns 2",
			sans:          []string{"*.example.org", "cert.example.org"},
			target:        "cert.example.org",
			allowWildcard: true,
			want:          2,
		},
		{
			name:          "exact before wildcard returns 2",
			sans:          []string{"cert.example.org", "*.example.org"},
			target:        "cert.example.org",
			allowWildcard: true,
			want:          2,
		},
		{
			name:          "exact case insensitive",
			sans:          []string{"*.Example.ORG", "CERT.Example.ORG"},
			target:        "cert.example.org",
			allowWildcard: false,
			want:          2,
		},
		{
			name:          "wildcard match allowed",
			sans:          []string{"*.example.org"},
			target:        "app.example.org",
			allowWildcard: true,
			want:          1,
		},
		{
			name:          "wildcard match disallowed",
			sans:          []string{"*.example.org"},
			target:        "app.example.org",
			allowWildcard: false,
			want:          0,
		},
		{
			name:          "wildcard does not match apex",
			sans:          []string{"*.example.org"},
			target:        "example.org",
			allowWildcard: true,
			want:          0,
		},
		{
			name:          "wildcard does not match multi level",
			sans:          []string{"*.example.org"},
			target:        "a.b.example.org",
			allowWildcard: true,
			want:          0,
		},
		{
			name:          "wildcard target exact match",
			sans:          []string{"example.org", "*.example.org"},
			target:        "*.example.org",
			allowWildcard: true,
			want:          2,
		},
		{
			name:          "wildcard target exact match with allowWildcard false",
			sans:          []string{"*.example.org"},
			target:        "*.example.org",
			allowWildcard: false,
			want:          2,
		},
		{
			name:          "wildcard target non match against host san",
			sans:          []string{"cert.example.org"},
			target:        "*.example.org",
			allowWildcard: true,
			want:          0,
		},
		{
			name:          "sub wildcard target not matched by parent wildcard",
			sans:          []string{"*.example.org"},
			target:        "*.sub.example.org",
			allowWildcard: true,
			want:          0,
		},
		{
			name:          "empty target",
			sans:          []string{"*.example.org"},
			target:        "   ",
			allowWildcard: true,
			want:          0,
		},
		{
			name:          "empty sans",
			sans:          nil,
			target:        "cert.example.org",
			allowWildcard: true,
			want:          0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := MatchScore(tc.sans, tc.target, tc.allowWildcard); got != tc.want {
				t.Fatalf("MatchScore(%v, %q, %v) = %d, want %d",
					tc.sans, tc.target, tc.allowWildcard, got, tc.want)
			}
		})
	}
}
