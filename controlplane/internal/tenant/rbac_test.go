package tenant

import "testing"

func TestCanCoversRBACMatrix(t *testing.T) {
	cases := []struct {
		action               Action
		owner, admin, viewer bool
	}{
		{ViewSites, true, true, true}, {ViewReports, true, true, true},
		{WriteRules, true, true, false}, {WriteProtection, true, true, false}, {AddSite, true, true, false}, {DeleteSite, true, true, false},
		{ManageMembers, true, true, false}, {ManageAPIKeys, true, true, false},
		{ManageBilling, true, false, false}, {DeleteOrganization, true, false, false}, {TransferOwner, true, false, false},
		{"unknown", false, false, false},
	}
	for _, tc := range cases {
		for _, row := range []struct {
			role Role
			want bool
		}{{Owner, tc.owner}, {Admin, tc.admin}, {Viewer, tc.viewer}} {
			if got := Can(row.role, tc.action, Resource{TenantID: "tenant"}); got != row.want {
				t.Errorf("Can(%s,%s)=%v want %v", row.role, tc.action, got, row.want)
			}
		}
	}
	if Can(Owner, ViewSites, Resource{}) {
		t.Fatal("empty tenant resource must be denied")
	}
}
