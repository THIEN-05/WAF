package wafcore

import (
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

func TestSnapshotYAMLRoundTrip(t *testing.T) {
	data, err := os.ReadFile("../../test/fixtures/snapshot.sample.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var fromYAML Snapshot
	if err = yaml.Unmarshal(data, &fromYAML); err != nil {
		t.Fatal(err)
	}
	if err = fromYAML.Validate(); err != nil {
		t.Fatal(err)
	}
	jsonData, err := json.Marshal(fromYAML)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON Snapshot
	if err = json.Unmarshal(jsonData, &fromJSON); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(fromYAML, fromJSON) {
		t.Fatalf("snapshot changed across YAML -> JSON round-trip\nYAML: %#v\nJSON: %#v", fromYAML, fromJSON)
	}
}

func TestDocumentedExpressions(t *testing.T) {
	cases := []struct {
		name, expr string
		ctx        MapCtx
		want       bool
	}{
		{"admin outside VN", "http.path starts_with '/admin' and ip.geo.country != 'VN'", MapCtx{Strings: map[string]string{"http.path": "/admin/settings", "ip.geo.country": "US"}}, true},
		{"tool user agent", "http.user_agent matches 'sqlmap|nikto|nmap'", MapCtx{Strings: map[string]string{"http.user_agent": "Mozilla sqlmap test"}}, true},
		{"post login bot score", "http.method == 'POST' and http.path == '/login' and bot.score > 70", MapCtx{Strings: map[string]string{"http.method": "POST", "http.path": "/login"}, Numbers: map[string]float64{"bot.score": 80}}, true},
		{"ip cidr set", "ip.src in_cidr {203.0.113.0/24, 198.51.100.0/24}", MapCtx{IPs: map[string]net.IP{"ip.src": net.ParseIP("203.0.113.8")}}, true},
		{"ip set membership", "ip.src in {203.0.113.0/24, 198.51.100.0/24}", MapCtx{IPs: map[string]net.IP{"ip.src": net.ParseIP("198.51.100.5")}}, true},
		{"header getter", "http.header['x-mode'] == 'safe'", MapCtx{Headers: map[string]string{"x-mode": "safe"}}, true},
		{"cookie getter", "http.cookie['sid'] == 'abc'", MapCtx{Cookies: map[string]string{"sid": "abc"}}, true},
		{"lower function", "lower(http.method) == 'post'", MapCtx{Strings: map[string]string{"http.method": "POST"}}, true},
		{"decode function", "url_decode(http.query) contains 'admin'", MapCtx{Strings: map[string]string{"http.query": "role%3Dadmin"}}, true},
		{"len function", "len(http.path) > 3", MapCtx{Strings: map[string]string{"http.path": "/long"}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fn, err := Compile(tc.expr, DefaultLimits())
			if err != nil {
				t.Fatal(err)
			}
			if got := fn(tc.ctx); got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}
}

func TestCompileErrorsHavePosition(t *testing.T) {
	cases := []string{"http.path ==\n  42", "http.path and true", "unknown.field == 'x'", "http.path matches '['", "http.path == \"double\""}
	for _, expr := range cases {
		_, err := Compile(expr, DefaultLimits())
		if err == nil {
			t.Errorf("%q accepted", expr)
			continue
		}
		ce, ok := err.(*CompileError)
		if !ok || ce.Pos.Line < 1 || ce.Pos.Column < 1 {
			t.Errorf("%q error lacks position: %#v", expr, err)
		}
	}
}

func TestDSLErrorGolden(t *testing.T) {
	cases := []struct{ name, expr, want string }{
		{"missing rhs", "http.path ==", "line 1, column 13: expected expression"},
		{"type mismatch on next line", "http.path ==\n  42", "line 1, column 11: comparison operands have incompatible types"},
		{"boolean operand", "http.path and true", "line 1, column 11: and requires boolean operands"},
		{"unknown field", "unknown.field == 'x'", "line 1, column 1: unknown field unknown.field"},
		{"bad regex", "http.path matches '['", "line 1, column 19: invalid RE2 pattern: error parsing regexp: missing closing ]: `[`"},
		{"double quote", "http.path == \"double\"", "line 1, column 14: unexpected character '\"'"},
		{"trailing operator", "http.path == 'x' and", "line 1, column 21: expected expression"},
		{"wrong len type", "len(req.size) > 1", "line 1, column 1: len() requires a string"},
		{"wrong not type", "not 'x'", "line 1, column 1: not requires a boolean"},
		{"set type mismatch", "http.path in {1}", "line 1, column 11: in set element type does not match left operand"},
		{"invalid cidr set", "ip.src in_cidr {'not-a-cidr'}", "line 1, column 17: in_cidr set values must be CIDR strings"},
		{"header key syntax", "http.header[x] == 'a'", "line 1, column 13: expected single-quoted field name"},
		{"dynamic regex", "http.path matches http.host", "line 1, column 19: matches pattern must be a string literal"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Compile(tc.expr, DefaultLimits())
			if err == nil {
				t.Fatal("expected compile error")
			}
			if got := err.Error(); got != tc.want {
				t.Fatalf("error = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestAdditionalDSLBranches(t *testing.T) {
	cases := []struct {
		expr string
		ctx  MapCtx
		want bool
	}{
		{"http.path != 'x'", MapCtx{Strings: map[string]string{"http.path": "y"}}, true},
		{"req.size >= 10", MapCtx{Numbers: map[string]float64{"req.size": 10}}, true},
		{"req.size <= 10", MapCtx{Numbers: map[string]float64{"req.size": 10}}, true},
		{"http.path ends_with 'bar'", MapCtx{Strings: map[string]string{"http.path": "foobar"}}, true},
		{"'x' in {'x', 'y'}", MapCtx{}, true},
		{"http.path contains 'admin'", MapCtx{Strings: map[string]string{"http.path": "/admin"}}, true},
		{"http.path starts_with 'z' or http.path starts_with '/'", MapCtx{Strings: map[string]string{"http.path": "/x"}}, true},
		{"http.path matches 'x'", MapCtx{Strings: map[string]string{"http.path": "x"}}, true},
	}
	for _, tc := range cases {
		fn, err := Compile(tc.expr, DefaultLimits())
		if err != nil {
			t.Errorf("%q: %v", tc.expr, err)
			continue
		}
		if got := fn(tc.ctx); got != tc.want {
			t.Errorf("%q got %v want %v", tc.expr, got, tc.want)
		}
	}
	for _, expr := range []string{"http.path == 'x' garbage", "http.path == 'x' and", "unknown() == 'x'", "len(req.size) > 1", "not 'x'", "http.path in {1}", "ip.src in_cidr {'not-a-cidr'}", "http.header[x] == 'a'", "http.path matches http.host"} {
		if _, err := Compile(expr, DefaultLimits()); err == nil {
			t.Errorf("expected %q to fail", expr)
		}
	}
}
func TestLimits(t *testing.T) {
	l := DefaultLimits()
	l.MaxExpressionBytes = 3
	if _, err := Compile("true == true", l); err == nil {
		t.Fatal("expected expression size error")
	}
	l = DefaultLimits()
	l.MaxNodes = 2
	if _, err := Compile("http.path == 'x'", l); err == nil {
		t.Fatal("expected node limit error")
	}
	l = DefaultLimits()
	l.MaxRegexBytes = 2
	if _, err := Compile("http.path matches 'long'", l); err == nil {
		t.Fatal("expected regex limit error")
	}
}
func TestActionValidation(t *testing.T) {
	for _, a := range []Action{{Type: "allow"}, {Type: "block", StatusCode: 403}, {Type: "rate_limit", Policy: "login"}, {Type: "tag", Tag: "x"}, {Type: "skip", Phase: "waf"}} {
		if err := a.Validate(); err != nil {
			t.Errorf("%+v: %v", a, err)
		}
	}
	if (Action{Type: "rate_limit"}).Validate() == nil {
		t.Fatal("expected missing policy error")
	}
}

func validSnapshot() Snapshot {
	return Snapshot{SchemaVersion: 1, Version: 2, GeneratedAt: time.Now().UTC(), Global: GlobalConfig{ManagedRuleset: "crs-lite"}, Sites: []Site{{ID: "s1", TenantID: "t1", Status: "active", Plan: "pro", Domains: []string{"example.com"}, Origins: []Origin{{URL: "https://origin.example", Weight: 1, TLSVerify: true}}, FailMode: "open", Rules: []Rule{{ID: "r1", Expression: "http.path == '/x'", Action: "block"}}}}}
}
func TestSnapshotValidateAndSignVerify(t *testing.T) {
	s := validSnapshot()
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	data, err := SignSnapshot(s, "key-a", priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := VerifySnapshot(data, map[string]ed25519.PublicKey{"key-a": pub})
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != s.Version {
		t.Fatalf("version=%d", got.Version)
	}
	if _, err = VerifySnapshot(data, map[string]ed25519.PublicKey{"other": pub}); err == nil {
		t.Fatal("expected unknown key error")
	}
}
func TestTamperedSnapshotRejected(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, err := SignSnapshot(validSnapshot(), "k1", priv)
	if err != nil {
		t.Fatal(err)
	}
	var env SignedSnapshot
	if err = json.Unmarshal(data, &env); err != nil {
		t.Fatal(err)
	}
	env.Payload[len(env.Payload)/2] ^= 1
	data, _ = json.Marshal(env)
	if _, err = VerifySnapshot(data, map[string]ed25519.PublicKey{"k1": pub}); err == nil {
		t.Fatal("tampered payload accepted")
	}
}
func TestSnapshotValidationErrors(t *testing.T) {
	s := validSnapshot()
	s.Sites[0].Origins = nil
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "origins") {
		t.Fatalf("unexpected error %v", err)
	}
}

func TestWAFConfigValidation(t *testing.T) {
	s := validSnapshot()
	s.Sites[0].Entitlements.MaxBodyBytes = 8192
	s.Sites[0].WAF.Sensitivity = "extreme"
	s.Sites[0].WAF.BodyLimitKB = 16
	if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "waf.sensitivity") || !strings.Contains(err.Error(), "body_limit_kb") {
		t.Fatalf("expected WAF sensitivity and entitlement validation, got %v", err)
	}
}
func TestLogAndStatsValidate(t *testing.T) {
	e := LogEvent{SchemaVersion: 1, TS: time.Now(), RequestID: "r", SiteID: "s", TenantID: "t", ClientIP: "192.0.2.1"}
	if err := e.Validate(); err != nil {
		t.Fatal(err)
	}
	s := SiteStats1m{Minute: time.Now().Truncate(time.Minute), SiteID: "s", TenantID: "t"}
	if err := s.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestValidationErrorCases(t *testing.T) {
	s := validSnapshot()
	s.SchemaVersion = 8
	s.Version = 0
	s.GeneratedAt = time.Time{}
	s.Global.ManagedRuleset = ""
	s.Sites = append(s.Sites, s.Sites[0])
	s.Sites[0].Status = "bad"
	s.Sites[0].FailMode = "bad"
	s.Sites[0].Plan = ""
	s.Sites[0].Domains = []string{"bad domain"}
	s.Sites[0].Origins = []Origin{{URL: "file:///tmp/x", Weight: -1}}
	s.Sites[0].WAF.Mode = "strange"
	s.Sites[0].WAF.BodyLimitKB = -1
	s.Sites[0].Entitlements.MaxRules = 0
	s.Sites[0].Rules = append(s.Sites[0].Rules, Rule{ID: "", Expression: "http.path matches 'long'", Action: "launch"})
	s.Sites[0].Entitlements.MaxRegexBytes = 2
	s.Sites[0].RateLimits = []RateLimit{{}}
	s.Sites[0].Access.BlockIPs = []string{"invalid"}
	if err := s.Validate(); err == nil {
		t.Fatal("expected combined schema validation errors")
	}
}

func TestLogStatsErrors(t *testing.T) {
	if (LogEvent{}).Validate() == nil {
		t.Fatal("expected log validation error")
	}
	if (SiteStats1m{}).Validate() == nil {
		t.Fatal("expected stats validation error")
	}
	s := SiteStats1m{Minute: time.Now(), TenantID: "t", SiteID: "s"}
	if s.Validate() == nil {
		t.Fatal("expected alignment error")
	}
}

func TestSignVerifyErrorCases(t *testing.T) {
	s := validSnapshot()
	if _, err := SignSnapshot(s, "", make([]byte, ed25519.PrivateKeySize)); err == nil {
		t.Fatal("expected empty kid error")
	}
	if _, err := SignSnapshot(s, "k", nil); err == nil {
		t.Fatal("expected private key error")
	}
	if _, err := VerifySnapshot([]byte("{"), nil); err == nil {
		t.Fatal("expected envelope decode error")
	}
	if _, err := VerifySnapshot([]byte(`{"schema_version":9,"kid":"k"}`), nil); err == nil {
		t.Fatal("expected envelope schema error")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, _ := SignSnapshot(s, "k", priv)
	if _, err := VerifySnapshot(data, map[string]ed25519.PublicKey{"k": []byte("bad")}); err == nil {
		t.Fatal("expected bad public key error")
	}
	var env SignedSnapshot
	_ = json.Unmarshal(data, &env)
	env.Signature = "zz"
	data, _ = json.Marshal(env)
	if _, err := VerifySnapshot(data, map[string]ed25519.PublicKey{"k": pub}); err == nil {
		t.Fatal("expected bad signature encoding")
	}
	_ = pub
}

func TestVerifyChecksumGzipAndPayloadFailures(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	data, err := SignSnapshot(validSnapshot(), "k", priv)
	if err != nil {
		t.Fatal(err)
	}
	var env SignedSnapshot
	_ = json.Unmarshal(data, &env)
	// Re-sign an invalid gzip body to reach decompression validation.
	badGzip := []byte("not gzip")
	sum := sha256.Sum256(badGzip)
	env.Payload = badGzip
	env.Checksum = hex.EncodeToString(sum[:])
	env.Signature = hex.EncodeToString(ed25519.Sign(priv, signatureMessage(env.KeyID, env.Checksum)))
	data, _ = json.Marshal(env)
	if _, err = VerifySnapshot(data, map[string]ed25519.PublicKey{"k": pub}); err == nil {
		t.Fatal("expected gzip error")
	}
	// A signed but invalid JSON payload reaches schema payload decoding.
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte("{"))
	_ = zw.Close()
	env.Payload = buf.Bytes()
	sum = sha256.Sum256(env.Payload)
	env.Checksum = hex.EncodeToString(sum[:])
	env.Signature = hex.EncodeToString(ed25519.Sign(priv, signatureMessage(env.KeyID, env.Checksum)))
	data, _ = json.Marshal(env)
	if _, err = VerifySnapshot(data, map[string]ed25519.PublicKey{"k": pub}); err == nil {
		t.Fatal("expected snapshot JSON error")
	}
}

func TestShortCircuitAndConstantOptimization(t *testing.T) {
	fn, err := Compile("false and http.path == 'x'", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if fn(MapCtx{}) {
		t.Fatal("false and ... evaluated true")
	}
	fn, err = Compile("not false and true == true", DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if !fn(MapCtx{}) {
		t.Fatal("constant expression should be true")
	}
}

func FuzzCompileNoPanic(f *testing.F) {
	for _, seed := range []string{"true == false", "http.path == '/admin'", "http.path matches '('", "ip.src in_cidr {203.0.113.0/24}", "not bot.score > 2", "http.header['x'] == 'y'"} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 8192 {
			return
		}
		_, _ = Compile(s, DefaultLimits())
	})
}

func BenchmarkRulesPerSecond(b *testing.B) {
	ctx := MapCtx{Strings: map[string]string{"http.path": "/admin/settings", "ip.geo.country": "US"}}
	for _, rules := range []int{1, 10, 100, 1000} {
		b.Run(strconv.Itoa(rules), func(b *testing.B) {
			compiled := make([]func(Ctx) bool, rules)
			for i := range compiled {
				fn, err := Compile("http.path starts_with '/admin' and ip.geo.country != 'VN'", DefaultLimits())
				if err != nil {
					b.Fatal(err)
				}
				compiled[i] = fn
			}
			b.ReportMetric(float64(rules*b.N)/b.Elapsed().Seconds(), "rules/s")
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				for _, fn := range compiled {
					_ = fn(ctx)
				}
			}
		})
	}
}
