package rules

import "testing"

func TestValidateCompilesAndChecksMode(t *testing.T) {
	if err := Validate(CustomRule{Expression: "http.path == '/private'", Action: "block", Mode: "log"}); err != nil {
		t.Fatal(err)
	}
	if err := Validate(CustomRule{Expression: "http.path ==", Action: "block", Mode: "enforce"}); err == nil {
		t.Fatal("invalid DSL passed")
	}
	if err := Validate(CustomRule{Expression: "true", Action: "block", Mode: "silent"}); err == nil {
		t.Fatal("invalid mode passed")
	}
}

func TestParseAccessCSVValidatesCIDR(t *testing.T) {
	rows, err := ParseAccessCSV("cidr,192.0.2.1/24,block,example\n")
	if err != nil {
		t.Fatal(err)
	}
	if rows[0][1] != "192.0.2.0/24" {
		t.Fatalf("CIDR not normalized: %q", rows[0][1])
	}
	if _, err := ParseAccessCSV("cidr,not-a-cidr,block,bad\n"); err == nil {
		t.Fatal("invalid CIDR passed")
	}
}
