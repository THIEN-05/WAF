package tenant

type Role string
type Action string

const (
	Owner  Role = "owner"
	Admin  Role = "admin"
	Viewer Role = "viewer"
)

const (
	ViewSites          Action = "sites:read"
	ViewReports        Action = "reports:read"
	WriteRules         Action = "rules:write"
	WriteProtection    Action = "protection:write"
	AddSite            Action = "sites:create"
	DeleteSite         Action = "sites:delete"
	ManageMembers      Action = "members:manage"
	ManageAPIKeys      Action = "api_keys:manage"
	ManageBilling      Action = "billing:manage"
	DeleteOrganization Action = "organization:delete"
	TransferOwner      Action = "organization:transfer_owner"
)

type Resource struct {
	TenantID string
	Kind     string
	ID       string
}

// Can is the only authorization decision point for tenant RBAC actions.
func Can(role Role, action Action, resource Resource) bool {
	if resource.TenantID == "" {
		return false
	}
	switch action {
	case ViewSites, ViewReports:
		return role == Owner || role == Admin || role == Viewer
	case WriteRules, WriteProtection, AddSite, DeleteSite, ManageAPIKeys:
		return role == Owner || role == Admin
	case ManageMembers:
		return role == Owner || role == Admin
	case ManageBilling, DeleteOrganization, TransferOwner:
		return role == Owner
	default:
		return false
	}
}
