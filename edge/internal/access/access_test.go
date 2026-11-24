package access

import (
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/example/wafplatform/edge/internal/reqctx"
	"github.com/example/wafplatform/pkg/wafcore"
)

func TestPrefixTreeIPv4AndIPv6(t *testing.T) {
	tree, err := NewPrefixTree([]string{"192.0.2.0/24", "2001:db8:1234::/48", "198.51.100.7"})
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{"192.0.2.44", "198.51.100.7", "2001:db8:1234::9"} {
		if !tree.Contains(net.ParseIP(raw)) {
			t.Errorf("prefix tree did not match %s", raw)
		}
	}
	for _, raw := range []string{"192.0.3.1", "198.51.100.8", "2001:db8:1235::1"} {
		if tree.Contains(net.ParseIP(raw)) {
			t.Errorf("prefix tree unexpectedly matched %s", raw)
		}
	}
	if _, err := NewPrefixTree([]string{"not-an-ip"}); err == nil {
		t.Fatal("invalid prefix accepted")
	}
}

type countingResolver struct {
	info  GeoInfo
	byIP  map[string]GeoInfo
	calls int
}

func (r *countingResolver) Resolve(ip net.IP) (GeoInfo, error) {
	r.calls++
	if info, ok := r.byIP[ip.String()]; ok {
		return info, nil
	}
	return r.info, nil
}

type attackChallenge struct{ calls int }

func (a *attackChallenge) Evaluate(*reqctx.RequestCtx) reqctx.Decision {
	a.calls++
	return reqctx.Decision{Action: reqctx.ActionChallenge, RuleID: "attack-gate", Reason: "under attack"}
}

func TestAccessEvaluationOrderAndGeoLookupCache(t *testing.T) {
	global, err := NewPrefixTree([]string{"203.0.113.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	resolver := &countingResolver{byIP: map[string]GeoInfo{
		"198.51.100.9":  {Country: "vn", ASN: 64512},
		"198.51.100.10": {Country: "us", ASN: 64512},
		"203.0.113.5":   {Country: "us", ASN: 64496},
	}}
	attack := &attackChallenge{}
	phase := NewPhase(resolver, nil, global, attack)
	site := wafcore.Site{
		ID: "site", Plan: "business",
		Access: wafcore.AccessConfig{AllowIPs: []string{"192.0.2.7"}, BlockIPs: []string{"192.0.2.0/24"}, BlockCountries: []string{"VN"}, BlockASNs: []uint32{64512}},
	}
	tests := []struct {
		name   string
		ip     string
		ruleID string
		action reqctx.Action
	}{
		{name: "site allow takes precedence", ip: "192.0.2.7", ruleID: "allow_ip", action: reqctx.ActionAllow},
		{name: "site IP block precedes geo", ip: "192.0.2.8", ruleID: "block_ip", action: reqctx.ActionBlock},
		{name: "country block", ip: "198.51.100.9", ruleID: "block_country", action: reqctx.ActionBlock},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ctx := newAccessContext(site, test.ip)
			decision := phase.Handle(ctx)
			if decision.Action != test.action || decision.RuleID != test.ruleID {
				t.Fatalf("decision=%+v", decision)
			}
		})
	}
	ctx := newAccessContext(site, "198.51.100.10")
	decision := phase.Handle(ctx)
	if decision.Action != reqctx.ActionBlock || decision.RuleID != "block_asn" {
		t.Fatalf("ASN decision=%+v", decision)
	}
	if resolver.calls != 2 {
		t.Fatalf("geo resolver calls=%d, want 2", resolver.calls)
	}

	site.Access = wafcore.AccessConfig{}
	phase = NewPhase(resolver, nil, global, attack)
	ctx = newAccessContext(site, "203.0.113.5")
	decision = phase.Handle(ctx)
	if decision.Action != reqctx.ActionBlock || decision.RuleID != "global_blocklist" {
		t.Fatalf("global list decision=%+v", decision)
	}
	ctx = newAccessContext(site, "198.51.100.10")
	decision = phase.Handle(ctx)
	if decision.Action != reqctx.ActionChallenge || decision.RuleID != "attack-gate" || decision.Phase != "access" {
		t.Fatalf("under-attack decision=%+v", decision)
	}
	if attack.calls != 1 {
		t.Fatalf("under-attack calls=%d, want 1", attack.calls)
	}
}

func TestAccessASNPolicyAndPlanEntitlement(t *testing.T) {
	resolver := &countingResolver{info: GeoInfo{Country: "US", ASN: 64512}}
	phase := NewPhase(resolver, nil, nil, nil)
	site := wafcore.Site{ID: "site", Plan: "business", Access: wafcore.AccessConfig{BlockASNs: []uint32{64512}}}
	decision := phase.Handle(newAccessContext(site, "198.51.100.1"))
	if decision.Action != reqctx.ActionBlock || decision.RuleID != "block_asn" {
		t.Fatalf("ASN decision=%+v", decision)
	}
	site.Plan = "free"
	phase = NewPhase(resolver, nil, nil, nil)
	decision = phase.Handle(newAccessContext(site, "198.51.100.1"))
	if decision.Action != reqctx.ActionBlock || decision.RuleID != "access_config" {
		t.Fatalf("free plan did not reject ASN policy: %+v", decision)
	}
}

func TestAccessGeoResolverErrorUsesSiteFailMode(t *testing.T) {
	resolver := failingGeoResolver{}
	for _, tc := range []struct {
		mode   string
		action reqctx.Action
		ruleID string
	}{{"open", reqctx.ActionAllow, "access_allow"}, {"closed", reqctx.ActionBlock, "geo_unavailable"}} {
		t.Run(tc.mode, func(t *testing.T) {
			site := wafcore.Site{ID: "site-" + tc.mode, Plan: "pro", FailMode: tc.mode,
				Access: wafcore.AccessConfig{BlockCountries: []string{"VN"}}}
			decision := NewPhase(resolver, nil, nil, nil).Handle(newAccessContext(site, "192.0.2.77"))
			if decision.Action != tc.action || decision.RuleID != tc.ruleID || decision.Phase != "access" {
				t.Fatalf("decision=%+v, want action=%v rule=%s", decision, tc.action, tc.ruleID)
			}
		})
	}
}

type failingGeoResolver struct{}

func (failingGeoResolver) Resolve(net.IP) (GeoInfo, error) {
	return GeoInfo{}, errors.New("database unavailable")
}

func TestAccessIPv4MappedIPv6AndAllowPrecedence(t *testing.T) {
	allow := net.ParseIP("192.0.2.9")
	tree, err := NewPrefixTree([]string{"::ffff:192.0.2.0/120"})
	if err != nil {
		t.Fatal(err)
	}
	if !tree.Contains(net.ParseIP("::ffff:192.0.2.9")) || !tree.Contains(allow) {
		t.Fatal("IPv4-mapped IPv6 prefix did not match mapped and native IPv4 addresses")
	}
	bans := NewBanTable(4, time.Now)
	if err := bans.Ban(allow, time.Minute); err != nil {
		t.Fatal(err)
	}
	site := wafcore.Site{ID: "precedence", Plan: "pro", Access: wafcore.AccessConfig{
		AllowIPs: []string{"192.0.2.9"}, BlockIPs: []string{"192.0.2.0/24"},
	}}
	decision := NewPhase(nil, bans, tree, nil).Handle(newAccessContext(site, "::ffff:192.0.2.9"))
	if decision.Action != reqctx.ActionAllow || decision.RuleID != "allow_ip" {
		t.Fatalf("allow list did not take precedence over ban/block: %+v", decision)
	}
}

func TestTemporaryBanCleanupRemovesExpiredEntries(t *testing.T) {
	now := time.Unix(100, 0)
	bans := NewBanTable(2, func() time.Time { return now })
	if err := bans.Ban(net.ParseIP("192.0.2.1"), time.Second); err != nil {
		t.Fatal(err)
	}
	if err := bans.Ban(net.ParseIP("192.0.2.2"), time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(2 * time.Second)
	if removed := bans.Cleanup(); removed != 1 {
		t.Fatalf("cleanup removed %d entries, want 1", removed)
	}
	if bans.IsBanned(net.ParseIP("192.0.2.1")) || !bans.IsBanned(net.ParseIP("192.0.2.2")) {
		t.Fatal("cleanup did not preserve only the active ban")
	}
}

func TestTemporaryBanExpiresAndRespectsCapacity(t *testing.T) {
	now := time.Unix(100, 0)
	bans := NewBanTable(1, func() time.Time { return now })
	first := net.ParseIP("192.0.2.1")
	if err := bans.Ban(first, 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if !bans.IsBanned(first) {
		t.Fatal("new ban not active")
	}
	if err := bans.Ban(net.ParseIP("192.0.2.2"), 5*time.Second); err == nil {
		t.Fatal("ban table exceeded configured capacity")
	}
	now = now.Add(6 * time.Second)
	if bans.IsBanned(first) || bans.Cleanup() != 0 {
		t.Fatal("expired ban remained active")
	}
	if err := bans.Ban(net.ParseIP("192.0.2.2"), time.Second); err != nil {
		t.Fatalf("expired key did not free capacity: %v", err)
	}
}

func TestFakeGeoResolverAndMMDBOpenErrors(t *testing.T) {
	resolver := FakeGeoResolver{"192.0.2.3": {Country: "VN", ASN: 64512}}
	info, err := resolver.Resolve(net.ParseIP("192.0.2.3"))
	if err != nil || info.Country != "VN" || info.ASN != 64512 {
		t.Fatalf("fake geodata=%+v err=%v", info, err)
	}
	if _, err = resolver.Resolve(net.ParseIP("192.0.2.4")); err == nil {
		t.Fatal("missing fake record should be visible to tests")
	}
	if _, err = OpenMMDB("", ""); err == nil {
		t.Fatal("OpenMMDB accepted empty paths")
	}
	path := filepath.Join(t.TempDir(), "invalid.mmdb")
	if err = os.WriteFile(path, []byte("not an mmdb"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = OpenMMDB(path, ""); err == nil {
		t.Fatal("OpenMMDB accepted invalid database")
	}
}

func TestMMDBFilesWhenOperatorDatabasesAreConfigured(t *testing.T) {
	countryPath := os.Getenv("EDGE_GEOIP_COUNTRY_MMDB")
	asnPath := os.Getenv("EDGE_GEOIP_ASN_MMDB")
	if countryPath == "" && asnPath == "" {
		t.Skip("set EDGE_GEOIP_COUNTRY_MMDB and/or EDGE_GEOIP_ASN_MMDB to run with licensed GeoLite2 files")
	}
	for _, path := range []string{countryPath, asnPath} {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			t.Skipf("configured MMDB file is unavailable at %q: %v", path, err)
		}
	}
	resolver, err := OpenMMDB(countryPath, asnPath)
	if err != nil {
		t.Fatalf("open configured MMDB files: %v", err)
	}
	t.Cleanup(func() {
		if err := resolver.Close(); err != nil {
			t.Errorf("close MMDB resolver: %v", err)
		}
	})
	if _, err = resolver.Resolve(net.ParseIP("1.1.1.1")); err != nil {
		t.Fatalf("lookup using configured MMDB files: %v", err)
	}
}

func newAccessContext(site wafcore.Site, clientIP string) *reqctx.RequestCtx {
	return &reqctx.RequestCtx{Site: &site, ClientIP: net.ParseIP(clientIP)}
}

func BenchmarkAccessCheck(b *testing.B) {
	site := wafcore.Site{ID: "bench", Plan: "pro", Access: wafcore.AccessConfig{BlockIPs: []string{"198.51.100.0/24"}}}
	phase := NewPhase(nil, nil, nil, nil)
	ctx := newAccessContext(site, "192.0.2.10")
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = phase.Handle(ctx)
	}
}
