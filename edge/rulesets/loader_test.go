package rulesets_test

import (
	"testing"

	"github.com/example/wafplatform/edge/internal/waf"
	"github.com/example/wafplatform/edge/rulesets"
)

func TestLoadEmbeddedManagedRules(t *testing.T) {
	loaded, err := rulesets.LoadEmbedded(256)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded) < 15 {
		t.Fatalf("loaded %d rules; expected the managed P4 ruleset", len(loaded))
	}
	if _, err := waf.NewPhase(loaded, nil); err != nil {
		t.Fatalf("managed rules did not compile: %v", err)
	}
}
