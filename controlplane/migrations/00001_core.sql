-- +goose Up
-- Application code generates UUIDv7 IDs; PostgreSQL stores them as native UUIDs.
CREATE TABLE plans (
  id uuid PRIMARY KEY, code text NOT NULL UNIQUE, price_minor bigint NOT NULL DEFAULT 0,
  currency char(3) NOT NULL DEFAULT 'USD', billing_interval text NOT NULL DEFAULT 'month',
  entitlements jsonb NOT NULL, version integer NOT NULL DEFAULT 1,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE users (
  id uuid PRIMARY KEY, email text NOT NULL, password_hash text NOT NULL,
  email_verified_at timestamptz, totp_secret_enc bytea, totp_enabled_at timestamptz, status text NOT NULL DEFAULT 'pending',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX users_email_lower_uq ON users (lower(email));
CREATE TABLE organizations (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL UNIQUE, name text NOT NULL,
  owner_user_id uuid NOT NULL REFERENCES users(id), plan_id uuid NOT NULL REFERENCES plans(id),
  status text NOT NULL DEFAULT 'active', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  CHECK (id = tenant_id)
);
ALTER TABLE users ADD COLUMN default_tenant_id uuid REFERENCES organizations(tenant_id);
CREATE TABLE memberships (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), user_id uuid NOT NULL REFERENCES users(id),
  role text NOT NULL CHECK (role IN ('owner','admin','viewer')), created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(),
  UNIQUE(tenant_id,user_id)
);
CREATE TABLE invitations (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), email text NOT NULL,
  role text NOT NULL CHECK (role IN ('admin','viewer')), token_hash bytea NOT NULL UNIQUE, expires_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE refresh_tokens (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), family_id uuid NOT NULL, token_hash bytea NOT NULL UNIQUE,
  user_agent text NOT NULL DEFAULT '', ip inet, expires_at timestamptz NOT NULL, revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX refresh_tokens_family_idx ON refresh_tokens(family_id);
CREATE TABLE api_keys (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), name text NOT NULL,
  key_hash bytea NOT NULL UNIQUE, scopes text[] NOT NULL, created_by uuid NOT NULL REFERENCES users(id),
  last_used_at timestamptz, expires_at timestamptz, revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE subscriptions (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), plan_id uuid NOT NULL REFERENCES plans(id),
  status text NOT NULL DEFAULT 'active', provider text NOT NULL DEFAULT 'free', provider_sub_id text,
  period_start timestamptz NOT NULL DEFAULT now(), period_end timestamptz, cancel_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE invoices (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), amount_minor bigint NOT NULL,
  currency char(3) NOT NULL, status text NOT NULL, provider_ref text, issued_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE webhook_events (
  id uuid PRIMARY KEY, provider text NOT NULL, event_id text NOT NULL, payload jsonb NOT NULL, processed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(provider,event_id)
);
CREATE TABLE sites (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), name text NOT NULL, status text NOT NULL DEFAULT 'pending',
  fail_mode text NOT NULL DEFAULT 'open', deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE domains (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), site_id uuid NOT NULL REFERENCES sites(id),
  hostname text NOT NULL UNIQUE, verification_token_hash bytea, verified_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE origins (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), site_id uuid NOT NULL REFERENCES sites(id),
  url text NOT NULL, weight integer NOT NULL DEFAULT 1, host_header text NOT NULL DEFAULT '', tls_mode text NOT NULL DEFAULT 'full_strict', health jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE waf_settings (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), site_id uuid NOT NULL UNIQUE REFERENCES sites(id),
  mode text NOT NULL DEFAULT 'enforce', sensitivity text NOT NULL DEFAULT 'medium', body_limit_kb integer NOT NULL DEFAULT 8,
  ruleset_version text NOT NULL DEFAULT '', exclusions jsonb NOT NULL DEFAULT '[]',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE rules (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), site_id uuid NOT NULL REFERENCES sites(id),
  priority integer NOT NULL DEFAULT 0, expression text NOT NULL, action text NOT NULL, action_params jsonb NOT NULL DEFAULT '{}',
  mode text NOT NULL DEFAULT 'enforce', enabled boolean NOT NULL DEFAULT true, expires_at timestamptz,
  version integer NOT NULL DEFAULT 1, deleted_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE rate_limit_policies (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), site_id uuid NOT NULL REFERENCES sites(id),
  match_expr text NOT NULL, key_expr text NOT NULL, request_limit bigint NOT NULL, window_seconds integer NOT NULL,
  action text NOT NULL, ban_seconds integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE access_lists (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), site_id uuid NOT NULL REFERENCES sites(id),
  type text NOT NULL, value text NOT NULL, action text NOT NULL, note text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE bot_settings (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), site_id uuid NOT NULL UNIQUE REFERENCES sites(id),
  settings jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE cache_settings (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), site_id uuid NOT NULL UNIQUE REFERENCES sites(id),
  settings jsonb NOT NULL DEFAULT '{}', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE certificates (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), domain_id uuid NOT NULL REFERENCES domains(id),
  status text NOT NULL, not_after timestamptz, secret_ref text NOT NULL, issuer text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE edges (
  id uuid PRIMARY KEY, region text NOT NULL, provider text NOT NULL, status text NOT NULL,
  snapshot_version bigint NOT NULL DEFAULT 0, last_heartbeat_at timestamptz, cert_serial text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE config_snapshots (
  id uuid PRIMARY KEY, scope text NOT NULL, version bigint NOT NULL, checksum text NOT NULL, signature bytea NOT NULL,
  object_key text NOT NULL, rollout_state text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(scope,version)
);
CREATE TABLE rule_history (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), entity text NOT NULL, entity_id uuid NOT NULL,
  version integer NOT NULL, diff jsonb NOT NULL, actor uuid REFERENCES users(id), at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE alert_rules (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), config jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE notification_channels (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), config jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE alerts (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), status text NOT NULL DEFAULT 'open', details jsonb NOT NULL DEFAULT '{}',
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE audit_logs (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), actor_type text NOT NULL, actor_id uuid,
  action text NOT NULL, entity text NOT NULL, entity_id uuid, ip inet, user_agent text NOT NULL DEFAULT '', diff jsonb NOT NULL DEFAULT '{}', at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE usage_counters (
  id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES organizations(tenant_id), period date NOT NULL,
  requests bigint NOT NULL DEFAULT 0, bytes_out bigint NOT NULL DEFAULT 0, rules_count integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(tenant_id,period)
);
CREATE TABLE email_verification_tokens (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), token_hash bytea NOT NULL UNIQUE, expires_at timestamptz NOT NULL, used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE password_reset_tokens (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), token_hash bytea NOT NULL UNIQUE, expires_at timestamptz NOT NULL, used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE totp_recovery_codes (
  id uuid PRIMARY KEY, user_id uuid NOT NULL REFERENCES users(id), code_hash bytea NOT NULL, used_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now(), UNIQUE(user_id,code_hash)
);

-- +goose StatementBegin
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='waf_api') THEN CREATE ROLE waf_api NOLOGIN NOBYPASSRLS; END IF;
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='waf_worker') THEN CREATE ROLE waf_worker NOLOGIN BYPASSRLS; END IF;
END $$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION lookup_invitation(p_hash bytea)
RETURNS TABLE(invitation_id uuid, tenant_id uuid, invited_email text, invited_role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path=public,pg_temp AS $$
BEGIN
  RETURN QUERY SELECT i.id,i.tenant_id,i.email,i.role FROM invitations i
  WHERE i.token_hash=p_hash AND i.expires_at>now() FOR UPDATE;
END $$;
-- +goose StatementEnd
ALTER FUNCTION lookup_invitation(bytea) OWNER TO waf_worker;
REVOKE ALL ON FUNCTION lookup_invitation(bytea) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION lookup_invitation(bytea) TO waf_api;
GRANT USAGE ON SCHEMA public TO waf_api, waf_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO waf_worker;
GRANT SELECT ON plans TO waf_api;
GRANT SELECT, INSERT, UPDATE ON users TO waf_api;
GRANT SELECT, INSERT, UPDATE ON refresh_tokens, email_verification_tokens, password_reset_tokens TO waf_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON totp_recovery_codes TO waf_api;
GRANT SELECT, INSERT, UPDATE ON organizations, sites, domains, origins, waf_settings, rules, rate_limit_policies, access_lists, bot_settings, cache_settings, certificates, rule_history, alert_rules, notification_channels, alerts, usage_counters TO waf_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON memberships, invitations, api_keys, subscriptions, invoices TO waf_api;
GRANT INSERT ON audit_logs TO waf_api, waf_worker;
REVOKE SELECT, UPDATE, DELETE ON audit_logs FROM waf_api, waf_worker;

-- +goose StatementBegin
DO $$
DECLARE t text;
BEGIN
  FOREACH t IN ARRAY ARRAY['organizations','memberships','invitations','api_keys','subscriptions','invoices','sites','domains','origins','waf_settings','rules','rate_limit_policies','access_lists','bot_settings','cache_settings','certificates','rule_history','alert_rules','notification_channels','alerts','audit_logs','usage_counters'] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
    EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid) WITH CHECK (tenant_id = NULLIF(current_setting(''app.tenant_id'', true), '''')::uuid)', t);
    IF t <> 'organizations' THEN EXECUTE format('CREATE INDEX %I ON %I(tenant_id)', t || '_tenant_id_idx', t); END IF;
  END LOOP;
END $$;
-- +goose StatementEnd

INSERT INTO plans(id,code,price_minor,currency,billing_interval,entitlements,version) VALUES
('01900000-0000-7000-8000-000000000001','free',0,'USD','month','{"version":1,"limits":{"sites":1,"custom_rules":3,"rate_limit_policies":1,"waf_body_kb":8,"log_retention_days":1},"features":{"waf_managed":"basic","bot":"none","geo_block":false,"asn_block":false,"cache":false,"api_access":false,"siem_export":false},"log_sample_rate":0.01}',1),
('01900000-0000-7000-8000-000000000002','pro',0,'USD','month','{"version":1,"limits":{"sites":5,"custom_rules":20,"rate_limit_policies":5,"waf_body_kb":64,"log_retention_days":7},"features":{"waf_managed":"full","bot":"js_challenge","geo_block":true,"asn_block":false,"cache":true,"api_access":false,"siem_export":false},"log_sample_rate":0.1}',1),
('01900000-0000-7000-8000-000000000003','business',0,'USD','month','{"version":1,"limits":{"sites":-1,"custom_rules":100,"rate_limit_policies":20,"waf_body_kb":128,"log_retention_days":30},"features":{"waf_managed":"full","bot":"captcha","geo_block":true,"asn_block":true,"cache":true,"api_access":true,"siem_export":false},"log_sample_rate":0.5}',1),
('01900000-0000-7000-8000-000000000004','enterprise',0,'USD','month','{"version":1,"limits":{"sites":-1,"custom_rules":-1,"rate_limit_policies":100,"waf_body_kb":256,"log_retention_days":90},"features":{"waf_managed":"full","bot":"custom","geo_block":true,"asn_block":true,"cache":true,"api_access":true,"siem_export":true},"log_sample_rate":1.0}',1)
ON CONFLICT(code) DO NOTHING;

-- +goose Down
REVOKE ALL ON SCHEMA public FROM waf_api, waf_worker;
DROP FUNCTION IF EXISTS lookup_invitation(bytea);
DROP TABLE IF EXISTS totp_recovery_codes,email_verification_tokens,password_reset_tokens,usage_counters,audit_logs,alerts,notification_channels,alert_rules,rule_history,config_snapshots,edges,certificates,cache_settings,bot_settings,access_lists,rate_limit_policies,rules,waf_settings,origins,domains,sites,webhook_events,invoices,subscriptions,api_keys,refresh_tokens,invitations,memberships,organizations,users,plans CASCADE;
-- +goose StatementBegin
DO $$ BEGIN IF EXISTS (SELECT FROM pg_roles WHERE rolname='waf_worker') THEN DROP ROLE waf_worker; END IF; IF EXISTS (SELECT FROM pg_roles WHERE rolname='waf_api') THEN DROP ROLE waf_api; END IF; END $$;
-- +goose StatementEnd
