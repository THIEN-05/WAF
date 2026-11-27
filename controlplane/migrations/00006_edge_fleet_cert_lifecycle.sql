-- +goose Up
ALTER TABLE public.edges
  ADD COLUMN dns_present boolean NOT NULL DEFAULT false,
  ADD COLUMN healthy_streak integer NOT NULL DEFAULT 0 CHECK (healthy_streak >= 0),
  ADD COLUMN unhealthy_streak integer NOT NULL DEFAULT 0 CHECK (unhealthy_streak >= 0),
  ADD COLUMN cert_not_after timestamptz,
  ADD COLUMN last_heartbeat jsonb NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN compromised_at timestamptz,
  ADD COLUMN decommissioned_at timestamptz;
-- `revoked` remains accepted for older internal snapshot fixtures; production lifecycle
-- transitions are enforced by fleet.Service and use edge_certificates for revocation.
ALTER TABLE public.edges ADD CONSTRAINT edges_status_check CHECK (status IN ('registering','ready','degraded','draining','offline','decommissioned','revoked','active'));

CREATE TABLE public.edge_bootstrap_tokens (
  id uuid PRIMARY KEY,
  edge_id uuid NOT NULL REFERENCES public.edges(id),
  token_hash bytea NOT NULL UNIQUE,
  expires_at timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now(),
  CHECK (octet_length(token_hash)=32)
);
CREATE INDEX edge_bootstrap_tokens_expiry_idx ON public.edge_bootstrap_tokens(expires_at) WHERE consumed_at IS NULL;

CREATE TABLE public.edge_certificates (
  serial text PRIMARY KEY,
  edge_id uuid NOT NULL REFERENCES public.edges(id),
  status text NOT NULL CHECK (status IN ('active','revoked','expired')),
  not_after timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX edge_certificates_edge_idx ON public.edge_certificates(edge_id,status);

CREATE TABLE public.edge_dns_withdrawal_limits (
  region text PRIMARY KEY,
  last_withdrawal_at timestamptz NOT NULL
);

ALTER TABLE public.certificates
  ADD COLUMN renewal_attempts integer NOT NULL DEFAULT 0 CHECK (renewal_attempts >= 0),
  ADD COLUMN next_attempt_at timestamptz,
  ADD COLUMN renewal_claimed_at timestamptz,
  ADD COLUMN last_error_code text NOT NULL DEFAULT '';

CREATE TABLE public.certificate_issuance_rate_limits (
  issuer_key text PRIMARY KEY,
  window_started_at timestamptz NOT NULL,
  orders_count integer NOT NULL CHECK (orders_count >= 0)
);

GRANT SELECT, INSERT, UPDATE ON public.edges, public.edge_bootstrap_tokens, public.edge_certificates TO waf_api;
GRANT SELECT, INSERT, UPDATE ON public.edges, public.edge_bootstrap_tokens, public.edge_certificates TO waf_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.edge_dns_withdrawal_limits TO waf_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.certificate_issuance_rate_limits TO waf_worker;

-- +goose Down
REVOKE ALL ON public.edge_bootstrap_tokens, public.edge_certificates FROM waf_api, waf_worker;
REVOKE ALL ON public.edge_dns_withdrawal_limits FROM waf_worker;
REVOKE ALL ON public.certificate_issuance_rate_limits FROM waf_worker;
REVOKE ALL ON public.edges FROM waf_api;
GRANT SELECT, INSERT, UPDATE, DELETE ON public.edges TO waf_worker;
ALTER TABLE public.certificates DROP COLUMN IF EXISTS last_error_code, DROP COLUMN IF EXISTS renewal_claimed_at, DROP COLUMN IF EXISTS next_attempt_at, DROP COLUMN IF EXISTS renewal_attempts;
DROP TABLE IF EXISTS public.edge_certificates;
DROP TABLE IF EXISTS public.edge_bootstrap_tokens;
DROP TABLE IF EXISTS public.edge_dns_withdrawal_limits;
DROP TABLE IF EXISTS public.certificate_issuance_rate_limits;
ALTER TABLE public.edges DROP CONSTRAINT IF EXISTS edges_status_check;
ALTER TABLE public.edges DROP COLUMN IF EXISTS decommissioned_at, DROP COLUMN IF EXISTS compromised_at,
  DROP COLUMN IF EXISTS last_heartbeat, DROP COLUMN IF EXISTS cert_not_after, DROP COLUMN IF EXISTS unhealthy_streak,
  DROP COLUMN IF EXISTS healthy_streak, DROP COLUMN IF EXISTS dns_present;
