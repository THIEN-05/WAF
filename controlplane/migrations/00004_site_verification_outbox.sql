-- +goose Up
ALTER TABLE public.domains ADD COLUMN verification_status text NOT NULL DEFAULT 'pending_dns';
ALTER TABLE public.domains ADD COLUMN verification_method text NOT NULL DEFAULT 'txt';
UPDATE public.domains SET verification_status='active' WHERE verified_at IS NOT NULL;
ALTER TABLE public.domains ADD CONSTRAINT domains_verification_status_check CHECK (verification_status IN ('pending_dns','active','failed'));
ALTER TABLE public.domains ADD CONSTRAINT domains_verification_method_check CHECK (verification_method IN ('txt','cname'));

CREATE TABLE public.config_change_outbox (
  id uuid PRIMARY KEY,
  tenant_id uuid NOT NULL REFERENCES public.organizations(tenant_id),
  site_id uuid NOT NULL REFERENCES public.sites(id),
  payload jsonb NOT NULL,
  published_at timestamptz,
  attempts integer NOT NULL DEFAULT 0,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE public.config_change_outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.config_change_outbox FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON public.config_change_outbox
  USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
  WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);
CREATE INDEX config_change_outbox_pending_idx ON public.config_change_outbox(created_at) WHERE published_at IS NULL;
GRANT SELECT, INSERT, UPDATE ON public.config_change_outbox TO waf_api, waf_worker;

-- +goose Down
DROP TABLE IF EXISTS public.config_change_outbox;
ALTER TABLE public.domains DROP CONSTRAINT IF EXISTS domains_verification_method_check;
ALTER TABLE public.domains DROP CONSTRAINT IF EXISTS domains_verification_status_check;
ALTER TABLE public.domains DROP COLUMN IF EXISTS verification_method;
ALTER TABLE public.domains DROP COLUMN IF EXISTS verification_status;
