-- +goose Up
ALTER TABLE public.users ADD COLUMN totp_last_step bigint NOT NULL DEFAULT -1;

ALTER TABLE public.users ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.users FORCE ROW LEVEL SECURITY;
CREATE POLICY user_isolation ON public.users
  USING (id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid)
  WITH CHECK (id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid);

ALTER TABLE public.refresh_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.refresh_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY user_isolation ON public.refresh_tokens
  USING (user_id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid)
  WITH CHECK (user_id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid);

ALTER TABLE public.totp_recovery_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.totp_recovery_codes FORCE ROW LEVEL SECURITY;
CREATE POLICY user_isolation ON public.totp_recovery_codes
  USING (user_id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid)
  WITH CHECK (user_id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid);

ALTER TABLE public.password_reset_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.password_reset_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY user_isolation ON public.password_reset_tokens
  USING (user_id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid)
  WITH CHECK (user_id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid);

ALTER TABLE public.email_verification_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.email_verification_tokens FORCE ROW LEVEL SECURITY;
CREATE POLICY user_isolation ON public.email_verification_tokens
  USING (user_id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid)
  WITH CHECK (user_id = NULLIF(pg_catalog.current_setting('app.user_id', true), '')::uuid);

-- Remove table grants inherited from migration 00001 before narrowing the public surface.
REVOKE SELECT, INSERT, UPDATE, DELETE ON public.users, public.refresh_tokens,
  public.totp_recovery_codes, public.password_reset_tokens,
  public.email_verification_tokens, public.invitations, public.api_keys,
  public.domains FROM waf_api;
GRANT SELECT(id,email,email_verified_at,totp_enabled_at,status,default_tenant_id,created_at,updated_at)
  ON public.users TO waf_api;
GRANT SELECT(id,user_agent,ip,expires_at,revoked_at,created_at,updated_at),
  UPDATE(revoked_at,updated_at) ON public.refresh_tokens TO waf_api;
REVOKE ALL ON public.totp_recovery_codes FROM waf_api;

-- The API cannot read credential/token hashes or write directly to identity tables.
REVOKE SELECT(password_hash,totp_secret_enc,totp_last_step),
  INSERT(password_hash,totp_secret_enc,totp_last_step),
  UPDATE(password_hash,totp_secret_enc,totp_last_step) ON public.users FROM waf_api;
REVOKE SELECT(token_hash),INSERT(token_hash),UPDATE(token_hash)
  ON public.refresh_tokens,public.email_verification_tokens,public.password_reset_tokens FROM waf_api;
REVOKE SELECT(code_hash),INSERT(code_hash),UPDATE(code_hash) ON public.totp_recovery_codes FROM waf_api;
REVOKE SELECT(token_hash),INSERT(token_hash),UPDATE(token_hash) ON public.invitations FROM waf_api;
REVOKE SELECT(key_hash),INSERT(key_hash),UPDATE(key_hash) ON public.api_keys FROM waf_api;
REVOKE SELECT(verification_token_hash),INSERT(verification_token_hash),
  UPDATE(verification_token_hash) ON public.domains FROM waf_api;

-- Narrow grants retain only the session metadata and revocation operation.
GRANT SELECT(id,user_id,family_id,user_agent,ip,expires_at,revoked_at,created_at,updated_at),
  UPDATE(revoked_at,updated_at) ON public.refresh_tokens TO waf_api;
GRANT SELECT(id,name,scopes,last_used_at,expires_at,revoked_at,created_at,tenant_id,created_by),
  UPDATE(revoked_at,updated_at) ON public.api_keys TO waf_api;
GRANT SELECT(id,tenant_id,site_id,hostname,verified_at,created_at,updated_at),
  INSERT(id,tenant_id,site_id,hostname,verified_at), UPDATE(verified_at,updated_at)
  ON public.domains TO waf_api;
REVOKE CREATE ON SCHEMA public FROM waf_api;

-- Identity functions are owned by a non-superuser, non-login, controlled worker role.
-- Every relation is schema-qualified and every function pins its search_path.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.lookup_invitation(p_hash bytea)
RETURNS TABLE(invitation_id uuid,tenant_id uuid,invited_email text,invited_role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  RETURN QUERY SELECT i.id,i.tenant_id,i.email,i.role FROM public.invitations AS i
    WHERE i.token_hash=p_hash AND i.expires_at>pg_catalog.now() FOR UPDATE;
END $$;

CREATE OR REPLACE FUNCTION public.auth_register_user(
  p_user_id uuid, p_email text, p_password_hash text, p_tenant_id uuid,
  p_member_id uuid, p_subscription_id uuid, p_token_id uuid,
  p_audit_id uuid, p_token_hash bytea, p_token_expires timestamptz
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
DECLARE v_plan_id uuid;
BEGIN
  SELECT id INTO STRICT v_plan_id FROM public.plans WHERE code='free';
  INSERT INTO public.users(id,email,password_hash,status)
    VALUES(p_user_id,p_email,p_password_hash,'pending');
  INSERT INTO public.organizations(id,tenant_id,name,owner_user_id,plan_id)
    VALUES(p_tenant_id,p_tenant_id,'Personal',p_user_id,v_plan_id);
  UPDATE public.users SET default_tenant_id=p_tenant_id,updated_at=pg_catalog.now() WHERE id=p_user_id;
  INSERT INTO public.memberships(id,tenant_id,user_id,role)
    VALUES(p_member_id,p_tenant_id,p_user_id,'owner');
  INSERT INTO public.subscriptions(id,tenant_id,plan_id,status,provider)
    VALUES(p_subscription_id,p_tenant_id,v_plan_id,'active','free');
  INSERT INTO public.email_verification_tokens(id,user_id,token_hash,expires_at)
    VALUES(p_token_id,p_user_id,p_token_hash,p_token_expires);
  INSERT INTO public.audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff)
    VALUES(p_audit_id,p_tenant_id,'user',p_user_id,'organization.create','organization',p_tenant_id,'{}'::jsonb);
END $$;

CREATE OR REPLACE FUNCTION public.auth_login_material(p_email text)
RETURNS TABLE(user_id uuid,password_hash text,status text,default_tenant_id uuid,
  totp_secret_enc bytea,totp_enabled_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.id,u.password_hash,u.status,u.default_tenant_id,u.totp_secret_enc,u.totp_enabled_at
  FROM public.users AS u WHERE pg_catalog.lower(u.email)=pg_catalog.lower(p_email)
  ORDER BY u.id LIMIT 1
$$;

CREATE OR REPLACE FUNCTION public.auth_consume_email_verification(p_hash bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_user_id uuid; v_token_id uuid;
BEGIN
  SELECT t.id,t.user_id INTO v_token_id,v_user_id FROM public.email_verification_tokens AS t
    WHERE t.token_hash=p_hash AND t.expires_at>pg_catalog.now() AND t.used_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  UPDATE public.users SET email_verified_at=pg_catalog.now(),status='active',updated_at=pg_catalog.now() WHERE id=v_user_id;
  UPDATE public.email_verification_tokens SET used_at=pg_catalog.now(),updated_at=pg_catalog.now() WHERE id=v_token_id;
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION public.auth_create_refresh(
  p_id uuid,p_user_id uuid,p_family_id uuid,p_hash bytea,p_user_agent text,p_ip inet,p_expires timestamptz
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  INSERT INTO public.refresh_tokens(id,user_id,family_id,token_hash,user_agent,ip,expires_at)
    VALUES(p_id,p_user_id,p_family_id,p_hash,p_user_agent,p_ip,p_expires);
END $$;

CREATE OR REPLACE FUNCTION public.auth_rotate_refresh(
  p_hash bytea,p_new_id uuid,p_new_hash bytea,p_new_expires timestamptz
) RETURNS TABLE(outcome text,user_id uuid,tenant_id uuid,role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_id uuid; v_uid uuid; v_family uuid; v_revoked timestamptz; v_exp timestamptz;
  v_tenant uuid; v_role text;
BEGIN
  SELECT rt.id,rt.user_id,rt.family_id,rt.revoked_at,rt.expires_at,u.default_tenant_id,m.role
    INTO v_id,v_uid,v_family,v_revoked,v_exp,v_tenant,v_role
    FROM public.refresh_tokens AS rt
    JOIN public.users AS u ON u.id=rt.user_id
    JOIN public.memberships AS m ON m.user_id=rt.user_id AND m.tenant_id=u.default_tenant_id
    WHERE rt.token_hash=p_hash FOR UPDATE OF rt;
  IF NOT FOUND THEN RETURN QUERY SELECT 'invalid'::text,'00000000-0000-0000-0000-000000000000'::uuid,'00000000-0000-0000-0000-000000000000'::uuid,''::text; RETURN; END IF;
  IF v_revoked IS NOT NULL THEN
    UPDATE public.refresh_tokens SET revoked_at=pg_catalog.now(),updated_at=pg_catalog.now()
      WHERE family_id=v_family AND revoked_at IS NULL;
    RETURN QUERY SELECT 'reuse'::text,v_uid,v_tenant,v_role; RETURN;
  END IF;
  IF v_exp<=pg_catalog.now() THEN RETURN QUERY SELECT 'invalid'::text,v_uid,v_tenant,v_role; RETURN; END IF;
  UPDATE public.refresh_tokens SET revoked_at=pg_catalog.now(),updated_at=pg_catalog.now() WHERE id=v_id;
  INSERT INTO public.refresh_tokens(id,user_id,family_id,token_hash,expires_at)
    VALUES(p_new_id,v_uid,v_family,p_new_hash,p_new_expires);
  RETURN QUERY SELECT 'ok'::text,v_uid,v_tenant,v_role;
END $$;

CREATE OR REPLACE FUNCTION public.auth_logout_refresh(p_hash bytea)
RETURNS void LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  UPDATE public.refresh_tokens SET revoked_at=pg_catalog.now(),updated_at=pg_catalog.now()
  WHERE token_hash=p_hash AND revoked_at IS NULL
$$;

CREATE OR REPLACE FUNCTION public.auth_password_reset_request(
  p_email text,p_id uuid,p_hash bytea,p_expires timestamptz
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_user_id uuid;
BEGIN
  SELECT u.id INTO v_user_id FROM public.users AS u
    WHERE pg_catalog.lower(u.email)=pg_catalog.lower(p_email) ORDER BY u.id LIMIT 1;
  IF FOUND THEN
    INSERT INTO public.password_reset_tokens(id,user_id,token_hash,expires_at)
      VALUES(p_id,v_user_id,p_hash,p_expires);
  END IF;
END $$;

CREATE OR REPLACE FUNCTION public.auth_complete_password_reset(p_hash bytea,p_password_hash text)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_token_id uuid; v_user_id uuid;
BEGIN
  SELECT t.id,t.user_id INTO v_token_id,v_user_id FROM public.password_reset_tokens AS t
    WHERE t.token_hash=p_hash AND t.expires_at>pg_catalog.now() AND t.used_at IS NULL FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  UPDATE public.users SET password_hash=p_password_hash,updated_at=pg_catalog.now() WHERE id=v_user_id;
  UPDATE public.password_reset_tokens SET used_at=pg_catalog.now(),updated_at=pg_catalog.now() WHERE id=v_token_id;
  UPDATE public.refresh_tokens SET revoked_at=pg_catalog.now(),updated_at=pg_catalog.now()
    WHERE user_id=v_user_id AND revoked_at IS NULL;
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION public.auth_configure_totp(
  p_user_id uuid,p_secret bytea,p_codes jsonb
) RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NULLIF(pg_catalog.current_setting('app.user_id',true),'') IS DISTINCT FROM p_user_id::text
     OR p_codes IS NULL OR pg_catalog.jsonb_typeof(p_codes)<>'array'
     OR pg_catalog.jsonb_array_length(p_codes)<>10 THEN RETURN false; END IF;
  UPDATE public.users SET totp_secret_enc=p_secret,totp_enabled_at=NULL,totp_last_step=-1,updated_at=pg_catalog.now()
    WHERE id=p_user_id;
  IF NOT FOUND THEN RETURN false; END IF;
  DELETE FROM public.totp_recovery_codes WHERE user_id=p_user_id;
  INSERT INTO public.totp_recovery_codes(id,user_id,code_hash)
    SELECT (code->>'id')::uuid,p_user_id,pg_catalog.decode(code->>'hash','base64')
      FROM pg_catalog.jsonb_array_elements(p_codes) AS codes(code);
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION public.auth_totp_secret()
RETURNS TABLE(secret bytea,enabled boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
  SELECT u.totp_secret_enc,(u.totp_enabled_at IS NOT NULL) FROM public.users AS u
  WHERE u.id=NULLIF(pg_catalog.current_setting('app.user_id',true),'')::uuid
$$;

CREATE OR REPLACE FUNCTION public.auth_consume_totp_step(p_step bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_user_id uuid; v_current bigint;
BEGIN
  v_user_id:=NULLIF(pg_catalog.current_setting('app.user_id',true),'')::uuid;
  IF v_user_id IS NULL THEN RETURN false; END IF;
  v_current:=pg_catalog.floor(EXTRACT(EPOCH FROM pg_catalog.clock_timestamp())/30)::bigint;
  IF p_step<v_current-1 OR p_step>v_current+1 THEN RETURN false; END IF;
  UPDATE public.users SET totp_last_step=p_step,updated_at=pg_catalog.now()
    WHERE id=v_user_id AND p_step>totp_last_step;
  RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION public.auth_enable_totp()
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_user_id uuid;
BEGIN
  v_user_id:=NULLIF(pg_catalog.current_setting('app.user_id',true),'')::uuid;
  IF v_user_id IS NULL THEN RETURN false; END IF;
  UPDATE public.users SET totp_enabled_at=pg_catalog.now(),updated_at=pg_catalog.now()
    WHERE id=v_user_id AND totp_secret_enc IS NOT NULL;
  RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION public.auth_consume_recovery_code(p_hash bytea)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_user_id uuid;
BEGIN
  v_user_id:=NULLIF(pg_catalog.current_setting('app.user_id',true),'')::uuid;
  IF v_user_id IS NULL THEN RETURN false; END IF;
  UPDATE public.totp_recovery_codes SET used_at=pg_catalog.now(),updated_at=pg_catalog.now()
    WHERE user_id=v_user_id AND code_hash=p_hash AND used_at IS NULL;
  RETURN FOUND;
END $$;

CREATE OR REPLACE FUNCTION public.audit_auth_mutation()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_row jsonb; v_user_id uuid; v_tenant_id uuid; v_entity_id uuid;
BEGIN
  IF TG_OP='DELETE' THEN v_row:=pg_catalog.to_jsonb(OLD); ELSE v_row:=pg_catalog.to_jsonb(NEW); END IF;
  IF TG_TABLE_NAME='users' THEN
    v_user_id:=(v_row->>'id')::uuid;
    v_tenant_id:=NULLIF(v_row->>'default_tenant_id','')::uuid;
    v_entity_id:=v_user_id;
  ELSE
    v_user_id:=(v_row->>'user_id')::uuid;
    v_entity_id:=(v_row->>'id')::uuid;
    SELECT u.default_tenant_id INTO v_tenant_id FROM public.users AS u WHERE u.id=v_user_id;
  END IF;
  IF v_tenant_id IS NOT NULL THEN
    INSERT INTO public.audit_logs(id,tenant_id,actor_type,action,entity,entity_id,diff)
      VALUES(pg_catalog.uuidv7(),v_tenant_id,'system',
        'auth.'||TG_TABLE_NAME||'.'||pg_catalog.lower(TG_OP),TG_TABLE_NAME,v_entity_id,
        pg_catalog.jsonb_build_object('operation',TG_OP));
  END IF;
  IF TG_OP='DELETE' THEN RETURN OLD; END IF;
  RETURN NEW;
END $$;

CREATE OR REPLACE FUNCTION public.tenant_create_api_key(
  p_id uuid,p_tenant uuid,p_name text,p_hash bytea,p_scopes text[],p_actor uuid,p_audit_id uuid,p_expires timestamptz
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NULLIF(pg_catalog.current_setting('app.tenant_id',true),'') IS DISTINCT FROM p_tenant::text
     OR NULLIF(pg_catalog.current_setting('app.user_id',true),'') IS DISTINCT FROM p_actor::text
     OR p_scopes IS NULL OR pg_catalog.cardinality(p_scopes)=0
     OR EXISTS (SELECT 1 FROM pg_catalog.unnest(p_scopes) AS s(scope)
       WHERE s.scope <> ALL(ARRAY['sites:read','rules:write','analytics:read']::text[]))
     OR NOT EXISTS (SELECT 1 FROM public.memberships WHERE tenant_id=p_tenant AND user_id=p_actor AND role IN ('owner','admin')) THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE='42501';
  END IF;
  INSERT INTO public.api_keys(id,tenant_id,name,key_hash,scopes,created_by,expires_at)
    VALUES(p_id,p_tenant,p_name,p_hash,p_scopes,p_actor,p_expires);
  INSERT INTO public.audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff)
    VALUES(p_audit_id,p_tenant,'user',p_actor,'api_key.create','api_key',p_id,
      pg_catalog.jsonb_build_object('name',p_name,'scopes',p_scopes));
END $$;

CREATE OR REPLACE FUNCTION public.tenant_create_invitation(
  p_id uuid,p_tenant uuid,p_email text,p_role text,p_hash bytea,p_expires timestamptz,p_actor uuid,p_audit_id uuid
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
BEGIN
  IF NULLIF(pg_catalog.current_setting('app.tenant_id',true),'') IS DISTINCT FROM p_tenant::text
     OR NULLIF(pg_catalog.current_setting('app.user_id',true),'') IS DISTINCT FROM p_actor::text
     OR p_role NOT IN ('admin','viewer') OR p_expires<=pg_catalog.now()
     OR p_expires>pg_catalog.now()+interval '7 days'
     OR NOT EXISTS (SELECT 1 FROM public.memberships WHERE tenant_id=p_tenant AND user_id=p_actor AND role IN ('owner','admin')) THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE='42501';
  END IF;
  INSERT INTO public.invitations(id,tenant_id,email,role,token_hash,expires_at)
    VALUES(p_id,p_tenant,p_email,p_role,p_hash,p_expires);
  INSERT INTO public.audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff)
    VALUES(p_audit_id,p_tenant,'user',p_actor,'member.invitation.create','invitation',p_id,
      pg_catalog.jsonb_build_object('email',p_email,'role',p_role));
END $$;

CREATE OR REPLACE FUNCTION public.tenant_accept_invitation(p_hash bytea,p_user_id uuid,p_member_id uuid,p_audit_id uuid)
RETURNS boolean LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_id uuid; v_tenant uuid; v_email text; v_role text; v_user_email text;
BEGIN
  IF NULLIF(pg_catalog.current_setting('app.user_id',true),'') IS DISTINCT FROM p_user_id::text THEN RETURN false; END IF;
  SELECT i.id,i.tenant_id,i.email,i.role INTO v_id,v_tenant,v_email,v_role
    FROM public.invitations AS i WHERE i.token_hash=p_hash AND i.expires_at>pg_catalog.now() FOR UPDATE;
  IF NOT FOUND THEN RETURN false; END IF;
  SELECT email INTO v_user_email FROM public.users WHERE id=p_user_id;
  IF v_user_email IS NULL OR pg_catalog.lower(pg_catalog.btrim(v_user_email))<>pg_catalog.lower(pg_catalog.btrim(v_email)) THEN RETURN false; END IF;
  INSERT INTO public.memberships(id,tenant_id,user_id,role) VALUES(p_member_id,v_tenant,p_user_id,v_role)
    ON CONFLICT(tenant_id,user_id) DO NOTHING;
  DELETE FROM public.invitations WHERE id=v_id;
  INSERT INTO public.audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff)
    VALUES(p_audit_id,v_tenant,'user',p_user_id,'member.invitation.accept','membership',p_member_id,
      pg_catalog.jsonb_build_object('role',v_role));
  RETURN true;
END $$;

CREATE OR REPLACE FUNCTION public.tenant_list_members(p_tenant uuid)
RETURNS TABLE(user_id uuid,email text,role text,created_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_user uuid;
BEGIN
  v_user:=NULLIF(pg_catalog.current_setting('app.user_id',true),'')::uuid;
  IF v_user IS NULL OR NULLIF(pg_catalog.current_setting('app.tenant_id',true),'') IS DISTINCT FROM p_tenant::text
     OR NOT EXISTS (SELECT 1 FROM public.memberships AS caller_m WHERE caller_m.tenant_id=p_tenant AND caller_m.user_id=v_user) THEN RETURN; END IF;
  RETURN QUERY SELECT m.user_id,u.email,m.role,m.created_at FROM public.memberships AS m
    JOIN public.users AS u ON u.id=m.user_id WHERE m.tenant_id=p_tenant ORDER BY m.created_at;
END $$;
-- +goose StatementEnd

CREATE TRIGGER audit_users_auth_mutation AFTER INSERT OR UPDATE OR DELETE ON public.users
  FOR EACH ROW EXECUTE FUNCTION public.audit_auth_mutation();
CREATE TRIGGER audit_refresh_tokens_auth_mutation AFTER INSERT OR UPDATE OR DELETE ON public.refresh_tokens
  FOR EACH ROW EXECUTE FUNCTION public.audit_auth_mutation();
CREATE TRIGGER audit_totp_recovery_auth_mutation AFTER INSERT OR UPDATE OR DELETE ON public.totp_recovery_codes
  FOR EACH ROW EXECUTE FUNCTION public.audit_auth_mutation();
CREATE TRIGGER audit_password_reset_auth_mutation AFTER INSERT OR UPDATE OR DELETE ON public.password_reset_tokens
  FOR EACH ROW EXECUTE FUNCTION public.audit_auth_mutation();
CREATE TRIGGER audit_email_verification_auth_mutation AFTER INSERT OR UPDATE OR DELETE ON public.email_verification_tokens
  FOR EACH ROW EXECUTE FUNCTION public.audit_auth_mutation();

-- Keep owner non-superuser: waf_worker is controlled, NOLOGIN and BYPASSRLS for background jobs.
GRANT CREATE ON SCHEMA public TO waf_worker;
ALTER FUNCTION public.auth_register_user(uuid,text,text,uuid,uuid,uuid,uuid,uuid,bytea,timestamptz) OWNER TO waf_worker;
ALTER FUNCTION public.lookup_invitation(bytea) OWNER TO waf_worker;
ALTER FUNCTION public.auth_login_material(text) OWNER TO waf_worker;
ALTER FUNCTION public.auth_consume_email_verification(bytea) OWNER TO waf_worker;
ALTER FUNCTION public.auth_create_refresh(uuid,uuid,uuid,bytea,text,inet,timestamptz) OWNER TO waf_worker;
ALTER FUNCTION public.auth_rotate_refresh(bytea,uuid,bytea,timestamptz) OWNER TO waf_worker;
ALTER FUNCTION public.auth_logout_refresh(bytea) OWNER TO waf_worker;
ALTER FUNCTION public.auth_password_reset_request(text,uuid,bytea,timestamptz) OWNER TO waf_worker;
ALTER FUNCTION public.auth_complete_password_reset(bytea,text) OWNER TO waf_worker;
ALTER FUNCTION public.auth_configure_totp(uuid,bytea,jsonb) OWNER TO waf_worker;
ALTER FUNCTION public.auth_totp_secret() OWNER TO waf_worker;
ALTER FUNCTION public.auth_consume_totp_step(bigint) OWNER TO waf_worker;
ALTER FUNCTION public.auth_enable_totp() OWNER TO waf_worker;
ALTER FUNCTION public.auth_consume_recovery_code(bytea) OWNER TO waf_worker;
ALTER FUNCTION public.audit_auth_mutation() OWNER TO waf_worker;
ALTER FUNCTION public.tenant_create_api_key(uuid,uuid,text,bytea,text[],uuid,uuid,timestamptz) OWNER TO waf_worker;
ALTER FUNCTION public.tenant_create_invitation(uuid,uuid,text,text,bytea,timestamptz,uuid,uuid) OWNER TO waf_worker;
ALTER FUNCTION public.tenant_accept_invitation(bytea,uuid,uuid,uuid) OWNER TO waf_worker;
ALTER FUNCTION public.tenant_list_members(uuid) OWNER TO waf_worker;

REVOKE ALL ON FUNCTION public.auth_register_user(uuid,text,text,uuid,uuid,uuid,uuid,uuid,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.lookup_invitation(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_login_material(text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_consume_email_verification(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_create_refresh(uuid,uuid,uuid,bytea,text,inet,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_rotate_refresh(bytea,uuid,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_logout_refresh(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_password_reset_request(text,uuid,bytea,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_complete_password_reset(bytea,text) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_configure_totp(uuid,bytea,jsonb) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_totp_secret() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_consume_totp_step(bigint) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_enable_totp() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.auth_consume_recovery_code(bytea) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.audit_auth_mutation() FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tenant_create_api_key(uuid,uuid,text,bytea,text[],uuid,uuid,timestamptz) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tenant_create_invitation(uuid,uuid,text,text,bytea,timestamptz,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tenant_accept_invitation(bytea,uuid,uuid,uuid) FROM PUBLIC;
REVOKE ALL ON FUNCTION public.tenant_list_members(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.lookup_invitation(bytea),public.auth_register_user(uuid,text,text,uuid,uuid,uuid,uuid,uuid,bytea,timestamptz),
  public.auth_login_material(text),public.auth_consume_email_verification(bytea),
  public.auth_create_refresh(uuid,uuid,uuid,bytea,text,inet,timestamptz),
  public.auth_rotate_refresh(bytea,uuid,bytea,timestamptz),public.auth_logout_refresh(bytea),
  public.auth_password_reset_request(text,uuid,bytea,timestamptz),
  public.auth_complete_password_reset(bytea,text),public.auth_configure_totp(uuid,bytea,jsonb),
  public.auth_totp_secret(),public.auth_consume_totp_step(bigint),public.auth_enable_totp(),
  public.auth_consume_recovery_code(bytea),
  public.tenant_create_api_key(uuid,uuid,text,bytea,text[],uuid,uuid,timestamptz),
  public.tenant_create_invitation(uuid,uuid,text,text,bytea,timestamptz,uuid,uuid),
  public.tenant_accept_invitation(bytea,uuid,uuid,uuid),public.tenant_list_members(uuid) TO waf_api;

-- +goose Down
REVOKE EXECUTE ON FUNCTION public.auth_register_user(uuid,text,text,uuid,uuid,uuid,uuid,uuid,bytea,timestamptz),
  public.auth_login_material(text),public.auth_consume_email_verification(bytea),
  public.auth_create_refresh(uuid,uuid,uuid,bytea,text,inet,timestamptz),
  public.auth_rotate_refresh(bytea,uuid,bytea,timestamptz),public.auth_logout_refresh(bytea),
  public.auth_password_reset_request(text,uuid,bytea,timestamptz),
  public.auth_complete_password_reset(bytea,text),public.auth_configure_totp(uuid,bytea,jsonb),
  public.auth_totp_secret(),public.auth_consume_totp_step(bigint),public.auth_enable_totp(),
  public.auth_consume_recovery_code(bytea),
  public.tenant_create_api_key(uuid,uuid,text,bytea,text[],uuid,uuid,timestamptz),
  public.tenant_create_invitation(uuid,uuid,text,text,bytea,timestamptz,uuid,uuid),
  public.tenant_accept_invitation(bytea,uuid,uuid,uuid),public.tenant_list_members(uuid) FROM waf_api;
DROP TRIGGER IF EXISTS audit_email_verification_auth_mutation ON public.email_verification_tokens;
DROP TRIGGER IF EXISTS audit_password_reset_auth_mutation ON public.password_reset_tokens;
DROP TRIGGER IF EXISTS audit_totp_recovery_auth_mutation ON public.totp_recovery_codes;
DROP TRIGGER IF EXISTS audit_refresh_tokens_auth_mutation ON public.refresh_tokens;
DROP TRIGGER IF EXISTS audit_users_auth_mutation ON public.users;
DROP FUNCTION IF EXISTS public.audit_auth_mutation();
DROP FUNCTION IF EXISTS public.tenant_list_members(uuid);
DROP FUNCTION IF EXISTS public.tenant_accept_invitation(bytea,uuid,uuid,uuid);
DROP FUNCTION IF EXISTS public.tenant_create_invitation(uuid,uuid,text,text,bytea,timestamptz,uuid,uuid);
DROP FUNCTION IF EXISTS public.tenant_create_api_key(uuid,uuid,text,bytea,text[],uuid,uuid,timestamptz);
DROP FUNCTION IF EXISTS public.auth_consume_recovery_code(bytea);
DROP FUNCTION IF EXISTS public.auth_enable_totp();
DROP FUNCTION IF EXISTS public.auth_consume_totp_step(bigint);
DROP FUNCTION IF EXISTS public.auth_totp_secret();
DROP FUNCTION IF EXISTS public.auth_configure_totp(uuid,bytea,jsonb);
DROP FUNCTION IF EXISTS public.auth_complete_password_reset(bytea,text);
DROP FUNCTION IF EXISTS public.auth_password_reset_request(text,uuid,bytea,timestamptz);
DROP FUNCTION IF EXISTS public.auth_logout_refresh(bytea);
DROP FUNCTION IF EXISTS public.auth_rotate_refresh(bytea,uuid,bytea,timestamptz);
DROP FUNCTION IF EXISTS public.auth_create_refresh(uuid,uuid,uuid,bytea,text,inet,timestamptz);
DROP FUNCTION IF EXISTS public.auth_consume_email_verification(bytea);
DROP FUNCTION IF EXISTS public.auth_login_material(text);
DROP FUNCTION IF EXISTS public.auth_register_user(uuid,text,text,uuid,uuid,uuid,uuid,uuid,bytea,timestamptz);
DROP POLICY IF EXISTS user_isolation ON public.email_verification_tokens;
DROP POLICY IF EXISTS user_isolation ON public.password_reset_tokens;
DROP POLICY IF EXISTS user_isolation ON public.totp_recovery_codes;
DROP POLICY IF EXISTS user_isolation ON public.refresh_tokens;
DROP POLICY IF EXISTS user_isolation ON public.users;
ALTER TABLE public.email_verification_tokens DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.password_reset_tokens DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.totp_recovery_codes DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.refresh_tokens DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.users DISABLE ROW LEVEL SECURITY;
ALTER TABLE public.users DROP COLUMN totp_last_step;
REVOKE CREATE ON SCHEMA public FROM waf_worker;
GRANT SELECT,INSERT,UPDATE ON public.users TO waf_api;
GRANT SELECT,INSERT,UPDATE ON public.refresh_tokens,public.email_verification_tokens,public.password_reset_tokens TO waf_api;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.totp_recovery_codes TO waf_api;
GRANT SELECT,INSERT,UPDATE,DELETE ON public.invitations,public.api_keys TO waf_api;
GRANT SELECT,INSERT,UPDATE ON public.domains TO waf_api;
