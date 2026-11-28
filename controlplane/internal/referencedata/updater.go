package referencedata

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/example/wafplatform/pkg/netguard"
	"github.com/oschwald/maxminddb-golang"
	"gopkg.in/yaml.v3"
)

type Kind string

const (
	Blocklist    Kind = "blocklist"
	GeoIP        Kind = "geoip"
	ManagedRules Kind = "managed_rules"
)

type Source struct {
	Name                  string
	Kind                  Kind
	URL                   string
	LicenseName           string
	LicenseURL            string
	RedistributionAllowed bool
	MaxBytes              int64
}

type Document struct {
	Version     string
	Checksum    string
	Bytes       []byte
	RecordCount int
}

type Fetcher interface {
	Fetch(context.Context, Source) ([]byte, error)
}
type Repository interface {
	Active(context.Context, Kind) (Document, error)
	Publish(context.Context, Kind, Document) error
}
type Publisher interface {
	PublishReference(context.Context, Kind, string, []byte) error
}
type WarningSink interface {
	Warn(context.Context, Source, string)
}
type Validator interface {
	Normalize(context.Context, Kind, []byte) ([]byte, int, error)
}

type Updater struct {
	Fetcher        Fetcher
	Repository     Repository
	Publisher      Publisher
	Warnings       WarningSink
	Validator      Validator
	MaxChangeRatio float64
	Now            func() time.Time
}

func (u Updater) Update(ctx context.Context, source Source) (Document, error) {
	if source.Name == "" || source.Kind == "" || source.LicenseName == "" || source.LicenseURL == "" || !source.RedistributionAllowed {
		return Document{}, errors.New("reference source license must explicitly allow redistribution")
	}
	if u.Fetcher == nil || u.Repository == nil || u.Publisher == nil || u.Validator == nil {
		return Document{}, errors.New("reference update dependencies are required")
	}
	if source.MaxBytes <= 0 {
		source.MaxBytes = 64 << 20
	}
	raw, err := u.Fetcher.Fetch(ctx, source)
	if err != nil {
		return Document{}, err
	}
	if int64(len(raw)) > source.MaxBytes {
		return Document{}, errors.New("reference source exceeds configured size limit")
	}
	normalized, count, err := u.Validator.Normalize(ctx, source.Kind, raw)
	if err != nil {
		return Document{}, fmt.Errorf("validate reference data: %w", err)
	}
	if len(normalized) == 0 || count == 0 {
		return Document{}, errors.New("reference data is empty")
	}
	active, activeErr := u.Repository.Active(ctx, source.Kind)
	if activeErr == nil && len(active.Bytes) > 0 {
		ratio := u.MaxChangeRatio
		if ratio <= 0 {
			ratio = .5
		}
		if anomalousChange(source.Kind, active.Bytes, normalized, ratio) {
			message := "reference update changed size/content beyond safety threshold; active version retained"
			if u.Warnings != nil {
				u.Warnings.Warn(ctx, source, message)
			}
			return active, errors.New(message)
		}
	} else if activeErr != nil && !errors.Is(activeErr, ErrNoActiveVersion) {
		return Document{}, activeErr
	}
	sum := sha256.Sum256(normalized)
	version := hex.EncodeToString(sum[:])
	doc := Document{Version: version, Checksum: version, Bytes: normalized, RecordCount: count}
	if err = u.Repository.Publish(ctx, source.Kind, doc); err != nil {
		return Document{}, err
	}
	if err = u.Publisher.PublishReference(ctx, source.Kind, version, normalized); err != nil {
		return Document{}, fmt.Errorf("publish reference snapshot: %w", err)
	}
	return doc, nil
}

var ErrNoActiveVersion = errors.New("no active reference version")

func anomalousChange(kind Kind, oldRaw, newRaw []byte, maxRatio float64) bool {
	if kind == GeoIP {
		ratio := float64(len(newRaw)) / float64(max(1, len(oldRaw)))
		return ratio < 0.5 || ratio > 2
	}
	oldCount, newCount := recordCount(oldRaw), recordCount(newRaw)
	if newCount*2 < oldCount {
		return true
	}
	oldSet, newSet := lineSet(oldRaw), lineSet(newRaw)
	changed := 0
	for item := range oldSet {
		if _, ok := newSet[item]; !ok {
			changed++
		}
	}
	for item := range newSet {
		if _, ok := oldSet[item]; !ok {
			changed++
		}
	}
	denom := len(oldSet)
	if len(newSet) > denom {
		denom = len(newSet)
	}
	if denom == 0 {
		return false
	}
	return float64(changed)/float64(denom) > maxRatio
}
func recordCount(raw []byte) int { return len(lineSet(raw)) }
func lineSet(raw []byte) map[string]struct{} {
	out := map[string]struct{}{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out[line] = struct{}{}
		}
	}
	return out
}

type BlocklistNormalizer struct{}

func (BlocklistNormalizer) Normalize(_ context.Context, kind Kind, raw []byte) ([]byte, int, error) {
	if kind != Blocklist {
		return nil, 0, errors.New("blocklist normalizer received another data kind")
	}
	lines := lineSet(raw)
	canonical := make(map[string]struct{}, len(lines))
	for line := range lines {
		_, network, err := net.ParseCIDR(line)
		if err != nil {
			return nil, 0, fmt.Errorf("invalid blocklist CIDR %q", line)
		}
		canonical[network.String()] = struct{}{}
	}
	normalized := make([]string, 0, len(canonical))
	for line := range canonical {
		normalized = append(normalized, line)
	}
	sort.Strings(normalized)
	return []byte(strings.Join(normalized, "\n") + "\n"), len(normalized), nil
}

type GeoIPNormalizer struct{}

func (GeoIPNormalizer) Normalize(_ context.Context, kind Kind, raw []byte) ([]byte, int, error) {
	if kind != GeoIP {
		return nil, 0, errors.New("GeoIP normalizer received another data kind")
	}
	reader, err := maxminddb.FromBytes(raw)
	if err != nil {
		return nil, 0, fmt.Errorf("invalid MMDB: %w", err)
	}
	_ = reader.Close()
	return append([]byte(nil), raw...), 1, nil
}

type ManagedRulesNormalizer struct{}
type managedRule struct {
	ID         string   `yaml:"id"`
	Phase      string   `yaml:"phase"`
	Pattern    string   `yaml:"pattern"`
	Severity   string   `yaml:"severity"`
	Paranoia   int      `yaml:"paranoia"`
	Targets    []string `yaml:"targets"`
	Transforms []string `yaml:"transforms"`
	Tags       []string `yaml:"tags"`
	Prefilter  []string `yaml:"prefilter"`
}

func (ManagedRulesNormalizer) Normalize(_ context.Context, kind Kind, raw []byte) ([]byte, int, error) {
	if kind != ManagedRules {
		return nil, 0, errors.New("managed rules normalizer received another data kind")
	}
	var rules []managedRule
	decoder := yaml.NewDecoder(strings.NewReader(string(raw)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&rules); err != nil {
		return nil, 0, err
	}
	if len(rules) == 0 || len(rules) > 1000 {
		return nil, 0, errors.New("managed rules count outside 1..1000")
	}
	seen := map[string]bool{}
	for _, rule := range rules {
		if rule.ID == "" || seen[rule.ID] || rule.Phase != "request" || len(rule.Pattern) == 0 || len(rule.Pattern) > 256 || rule.Paranoia < 1 || rule.Paranoia > 4 || len(rule.Targets) == 0 || !hasOWASPTag(rule.Tags) || !validSeverity(rule.Severity) {
			return nil, 0, fmt.Errorf("invalid managed rule %q", rule.ID)
		}
		seen[rule.ID] = true
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return nil, 0, fmt.Errorf("rule %s invalid RE2: %w", rule.ID, err)
		}
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].ID < rules[j].ID })
	normalized, err := yaml.Marshal(rules)
	return normalized, len(rules), err
}

type CompositeNormalizer struct{}

func (CompositeNormalizer) Normalize(ctx context.Context, kind Kind, raw []byte) ([]byte, int, error) {
	switch kind {
	case Blocklist:
		return (BlocklistNormalizer{}).Normalize(ctx, kind, raw)
	case GeoIP:
		return (GeoIPNormalizer{}).Normalize(ctx, kind, raw)
	case ManagedRules:
		return (ManagedRulesNormalizer{}).Normalize(ctx, kind, raw)
	default:
		return nil, 0, errors.New("unsupported reference data kind")
	}
}

// HTTPSFetcher rejects redirects and routes every connection through netguard so
// configuration cannot turn scheduled reference downloads into an SSRF primitive.
type HTTPSFetcher struct {
	Guard   netguard.Guard
	Client  *http.Client
	Timeout time.Duration
}

func (f HTTPSFetcher) Fetch(ctx context.Context, source Source) ([]byte, error) {
	u, err := url.Parse(source.URL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("reference source URL must be HTTPS")
	}
	client := f.Client
	if client == nil {
		timeout := f.Timeout
		if timeout <= 0 {
			timeout = 15 * time.Second
		}
		transport := &http.Transport{DialContext: f.Guard.DialContext}
		client = &http.Client{Timeout: timeout, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("reference fetch returned status %d", response.StatusCode)
	}
	max := source.MaxBytes
	if max <= 0 {
		max = 64 << 20
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, errors.New("reference source exceeds configured size limit")
	}
	return body, nil
}

func hasOWASPTag(tags []string) bool {
	for _, tag := range tags {
		if strings.HasPrefix(tag, "owasp-") {
			return true
		}
	}
	return false
}
func validSeverity(value string) bool {
	switch value {
	case "critical", "error", "warning", "notice":
		return true
	default:
		return false
	}
}
