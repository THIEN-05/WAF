-- name: GetMembershipRole :one
SELECT role FROM memberships WHERE tenant_id = sqlc.arg(tenant_id) AND user_id = sqlc.arg(user_id);

-- name: ListTenantSites :many
SELECT id, name, status FROM sites WHERE tenant_id = sqlc.arg(tenant_id) AND deleted_at IS NULL ORDER BY created_at DESC;

-- name: InsertAuditLog :exec
INSERT INTO audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff)
VALUES(sqlc.arg(id),sqlc.arg(tenant_id),sqlc.arg(actor_type),sqlc.narg(actor_id),sqlc.arg(action),sqlc.arg(entity),sqlc.narg(entity_id),sqlc.arg(diff));
