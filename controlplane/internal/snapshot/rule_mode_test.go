package snapshot

import "testing"

func TestRuleModeFromDatabaseMatchesWAFCoreContract(t *testing.T) {
	for _, test := range []struct {
		databaseMode string
		want         string
	}{
		{databaseMode: "enforce", want: ""},
		{databaseMode: "log", want: "log"},
		{databaseMode: "unknown", want: "unknown"},
	} {
		if got := ruleModeFromDatabase(test.databaseMode); got != test.want {
			t.Errorf("ruleModeFromDatabase(%q)=%q, want %q", test.databaseMode, got, test.want)
		}
	}
}
