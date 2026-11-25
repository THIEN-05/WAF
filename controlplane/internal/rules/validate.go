package rules

import (
	"encoding/csv"
	"fmt"
	"net"
	"strings"

	"github.com/example/wafplatform/pkg/wafcore"
)

type CustomRule struct {
	Expression string `json:"expression"`
	Action     string `json:"action"`
	Mode       string `json:"mode"`
	Priority   int    `json:"priority"`
}

// Validate compiles the DSL before persistence and rejects unsupported actions/modes.
func Validate(rule CustomRule) error {
	if _, err := wafcore.Compile(rule.Expression, wafcore.DefaultLimits()); err != nil {
		return fmt.Errorf("expression: %w", err)
	}
	switch rule.Action {
	case "allow", "block", "challenge", "log", "rate_limit", "tag", "skip":
	default:
		return fmt.Errorf("unsupported action %q", rule.Action)
	}
	if rule.Mode != "log" && rule.Mode != "enforce" {
		return fmt.Errorf("mode must be log or enforce")
	}
	return nil
}

// ParseAccessCSV validates rows as type,value,action,note and normalizes CIDRs.
func ParseAccessCSV(raw string) ([][]string, error) {
	r := csv.NewReader(strings.NewReader(raw))
	r.FieldsPerRecord = 4
	r.TrimLeadingSpace = true
	rows, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	for i := range rows {
		kind, value, action := strings.ToLower(strings.TrimSpace(rows[i][0])), strings.TrimSpace(rows[i][1]), strings.ToLower(strings.TrimSpace(rows[i][2]))
		if action != "allow" && action != "block" {
			return nil, fmt.Errorf("row %d: action must be allow or block", i+1)
		}
		switch kind {
		case "ip":
			if net.ParseIP(value) == nil {
				return nil, fmt.Errorf("row %d: invalid IP", i+1)
			}
		case "cidr":
			_, network, e := net.ParseCIDR(value)
			if e != nil {
				return nil, fmt.Errorf("row %d: invalid CIDR", i+1)
			}
			rows[i][1] = network.String()
		case "country", "asn":
			if value == "" {
				return nil, fmt.Errorf("row %d: empty value", i+1)
			}
		default:
			return nil, fmt.Errorf("row %d: unsupported access-list type", i+1)
		}
		rows[i][0], rows[i][2] = kind, action
	}
	return rows, nil
}
