-- +goose Up
ALTER TABLE public.domains ADD COLUMN verification_status text NOT NULL DEFAULT 'pending_dns';
ALTER TABLE public.domains ADD COLUMN verification_method text NOT NULL DEFAULT 'txt';
ALTER TABLE public.domains ADD COLUMN verification_expires_at timestamptz;
ALTER TABLE public.domains ADD COLUMN next_verification_at timestamptz NOT NULL DEFAULT now();
UPDATE public.domains SET verification_status='active' WHERE verified_at IS NOT NULL;
UPDATE public.domains SET verification_expires_at=now()+interval '24 hours',next_verification_at=now()
  WHERE verification_status='pending_dns' AND verification_expires_at IS NULL;
ALTER TABLE public.domains ADD CONSTRAINT domains_verification_status_check CHECK (verification_status IN ('pending_dns','active','failed'));
ALTER TABLE public.domains ADD CONSTRAINT domains_verification_method_check CHECK (verification_method IN ('txt','cname'));

UPDATE public.sites SET status='pending_dns' WHERE status='pending';
ALTER TABLE public.sites ADD CONSTRAINT sites_status_check CHECK (status IN ('pending_dns','active','suspended','deleted'));
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.enforce_site_status_transition() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
  IF NEW.status = OLD.status THEN RETURN NEW; END IF;
  IF (OLD.status='pending_dns' AND NEW.status IN ('active','suspended','deleted'))
     OR (OLD.status='active' AND NEW.status IN ('suspended','deleted'))
     OR (OLD.status='suspended' AND NEW.status IN ('active','deleted')) THEN
    IF NEW.status='deleted' THEN NEW.deleted_at := COALESCE(NEW.deleted_at,now()); END IF;
    RETURN NEW;
  END IF;
  RAISE EXCEPTION 'invalid site status transition' USING ERRCODE='23514';
END $$;
-- +goose StatementEnd
CREATE TRIGGER sites_status_transition BEFORE UPDATE OF status ON public.sites
  FOR EACH ROW EXECUTE FUNCTION public.enforce_site_status_transition();

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
REVOKE ALL ON public.config_change_outbox FROM PUBLIC, waf_api, waf_worker;
GRANT INSERT (id,tenant_id,site_id,payload) ON public.config_change_outbox TO waf_api;
GRANT SELECT (id,tenant_id,site_id,payload,attempts,created_at,published_at),
  INSERT (id,tenant_id,site_id,payload), UPDATE (published_at,attempts,updated_at)
  ON public.config_change_outbox TO waf_worker;

-- The API never receives direct write/read privileges for the domain verification hash.
-- This entrypoint binds actor and tenant to the transaction-local request identity.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.site_add_domain(
  p_id uuid, p_tenant_id uuid, p_site_id uuid, p_hostname text,
  p_verification_hash bytea, p_expires_at timestamptz, p_actor_id uuid, p_audit_id uuid
) RETURNS void
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
  actor_role text;
  target_site_status text;
BEGIN
  IF NULLIF(current_setting('app.tenant_id', true),'') IS DISTINCT FROM p_tenant_id::text
     OR NULLIF(current_setting('app.user_id', true),'') IS DISTINCT FROM p_actor_id::text THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE='42501';
  END IF;
  SELECT role INTO actor_role FROM public.memberships
    WHERE tenant_id=p_tenant_id AND user_id=p_actor_id FOR SHARE;
  IF actor_role IS NULL OR actor_role NOT IN ('owner','admin') THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE='42501';
  END IF;
  IF octet_length(p_verification_hash) <> 32 OR p_expires_at <= now() OR p_expires_at > now()+interval '24 hours' THEN
    RAISE EXCEPTION 'invalid verification proof' USING ERRCODE='22023';
  END IF;
  SELECT status INTO target_site_status FROM public.sites WHERE id=p_site_id AND tenant_id=p_tenant_id AND deleted_at IS NULL FOR UPDATE;
  IF target_site_status IS NULL THEN
    RAISE EXCEPTION 'not found' USING ERRCODE='P0002';
  END IF;
  INSERT INTO public.domains(id,tenant_id,site_id,hostname,verification_token_hash,verification_status,verification_method,verification_expires_at,next_verification_at)
    VALUES(p_id,p_tenant_id,p_site_id,p_hostname,p_verification_hash,'pending_dns','txt',p_expires_at,now()+interval '1 minute');
  INSERT INTO public.audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff)
    VALUES(p_audit_id,p_tenant_id,'user',p_actor_id,'domain.add','domain',p_id,jsonb_build_object('hostname',p_hostname));
END $$;
-- +goose StatementEnd
ALTER FUNCTION public.site_add_domain(uuid,uuid,uuid,text,bytea,timestamptz,uuid,uuid) OWNER TO waf_worker;
REVOKE ALL ON FUNCTION public.site_add_domain(uuid,uuid,uuid,text,bytea,timestamptz,uuid,uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.site_add_domain(uuid,uuid,uuid,text,bytea,timestamptz,uuid,uuid) TO waf_api;

-- +goose Down
REVOKE ALL ON FUNCTION public.site_add_domain(uuid,uuid,uuid,text,bytea,timestamptz,uuid,uuid) FROM PUBLIC,waf_api;
DROP FUNCTION IF EXISTS public.site_add_domain(uuid,uuid,uuid,text,bytea,timestamptz,uuid,uuid);
DROP TRIGGER IF EXISTS sites_status_transition ON public.sites;
DROP FUNCTION IF EXISTS public.enforce_site_status_transition();
DROP TABLE IF EXISTS public.config_change_outbox;
UPDATE public.sites SET status='pending' WHERE status='pending_dns';
ALTER TABLE public.sites DROP CONSTRAINT IF EXISTS sites_status_check;
ALTER TABLE public.domains DROP COLUMN IF EXISTS next_verification_at;
ALTER TABLE public.domains DROP COLUMN IF EXISTS verification_expires_at;
ALTER TABLE public.domains DROP CONSTRAINT IF EXISTS domains_verification_method_check;
ALTER TABLE public.domains DROP CONSTRAINT IF EXISTS domains_verification_status_check;
ALTER TABLE public.domains DROP COLUMN IF EXISTS verification_method;
ALTER TABLE public.domains DROP COLUMN IF EXISTS verification_status;
