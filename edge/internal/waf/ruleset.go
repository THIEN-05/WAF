package waf

import (
	"fmt"
	"io"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

const maxManagedRules = 1000

type Rule struct {
	ID         string   `yaml:"id"`
	Phase      string   `yaml:"phase"`
	Targets    []string `yaml:"targets"`
	Transforms []string `yaml:"transforms"`
	Pattern    string   `yaml:"pattern"`
	Severity   string   `yaml:"severity"`
	Paranoia   int      `yaml:"paranoia"`
	Tags       []string `yaml:"tags"`
	Prefilter  []string `yaml:"prefilter,omitempty"`
}

type compiledRule struct {
	rule      Rule
	pattern   *regexp.Regexp
	points    int
	prefilter map[string]struct{}
}

func LoadYAML(reader io.Reader, maxRegexBytes int) ([]Rule, error) {
	if maxRegexBytes <= 0 {
		maxRegexBytes = 256
	}
	decoder := yaml.NewDecoder(reader)
	decoder.KnownFields(true)
	var rules []Rule
	if err := decoder.Decode(&rules); err != nil {
		return nil, fmt.Errorf("decode managed WAF rules: %w", err)
	}
	if len(rules) > maxManagedRules {
		return nil, fmt.Errorf("managed WAF rules exceed limit %d", maxManagedRules)
	}
	seen := make(map[string]struct{}, len(rules))
	for i, rule := range rules {
		if rule.ID == "" || rule.Phase != "request" || len(rule.Targets) == 0 {
			return nil, fmt.Errorf("rules[%d]: id, request phase, and targets are required", i)
		}
		if _, ok := seen[rule.ID]; ok {
			return nil, fmt.Errorf("rules[%d]: duplicate id %q", i, rule.ID)
		}
		seen[rule.ID] = struct{}{}
		if len(rule.Pattern) == 0 || len(rule.Pattern) > maxRegexBytes {
			return nil, fmt.Errorf("rule %s: regex size %d outside limit 1..%d", rule.ID, len(rule.Pattern), maxRegexBytes)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return nil, fmt.Errorf("rule %s: invalid RE2 pattern: %w", rule.ID, err)
		}
		if _, ok := severityPoints[rule.Severity]; !ok {
			return nil, fmt.Errorf("rule %s: unsupported severity %q", rule.ID, rule.Severity)
		}
		if rule.Paranoia < 1 || rule.Paranoia > 4 {
			return nil, fmt.Errorf("rule %s: paranoia must be between 1 and 4", rule.ID)
		}
		hasOWASPTag := false
		for _, tag := range rule.Tags {
			if strings.TrimSpace(tag) == "" {
				return nil, fmt.Errorf("rule %s: tags must not be empty", rule.ID)
			}
			if strings.HasPrefix(tag, "owasp-") {
				hasOWASPTag = true
			}
		}
		if !hasOWASPTag {
			return nil, fmt.Errorf("rule %s: at least one owasp-* tag is required", rule.ID)
		}
		for _, target := range rule.Targets {
			if target != "path" && target != "args" && target != "body" && target != "cookies" && target != "headers" && target != "protocol" {
				return nil, fmt.Errorf("rule %s: unsupported target %q", rule.ID, target)
			}
		}
		for _, transform := range rule.Transforms {
			if transform != "url_decode" && transform != "lowercase" && transform != "remove_sql_comments" && transform != "html_entity_decode" && transform != "remove_nul" && transform != "path_normalize" && transform != "compress_whitespace" {
				return nil, fmt.Errorf("rule %s: unsupported transform %q", rule.ID, transform)
			}
		}
		for _, word := range rule.Prefilter {
			if strings.TrimSpace(word) == "" || len(word) > maxTargetBytes {
				return nil, fmt.Errorf("rule %s: invalid prefilter term", rule.ID)
			}
		}
	}
	return rules, nil
}

func compileRules(rules []Rule) ([]compiledRule, *automaton, error) {
	compiled := make([]compiledRule, 0, len(rules))
	words := make([]string, 0)
	ids := make(map[string]struct{}, len(rules))
	for _, rule := range rules {
		if rule.ID == "" {
			return nil, nil, fmt.Errorf("managed WAF rule has empty id")
		}
		if _, exists := ids[rule.ID]; exists {
			return nil, nil, fmt.Errorf("duplicate managed WAF rule id %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		pattern, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return nil, nil, fmt.Errorf("rule %s: %w", rule.ID, err)
		}
		entry := compiledRule{rule: rule, pattern: pattern, points: severityPoints[rule.Severity], prefilter: make(map[string]struct{}, len(rule.Prefilter))}
		for _, word := range rule.Prefilter {
			word = strings.ToLower(word)
			entry.prefilter[word] = struct{}{}
			words = append(words, word)
		}
		compiled = append(compiled, entry)
	}
	return compiled, newAutomaton(words), nil
}

var severityPoints = map[string]int{"critical": 5, "error": 4, "warning": 3, "notice": 2}
