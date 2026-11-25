-- +goose Up
-- Session creation is only permitted for the identity established by the caller's
-- password/TOTP verification and pinned with WithUserTx.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.auth_create_refresh(
  p_id uuid,p_user_id uuid,p_family_id uuid,p_hash bytea,p_user_agent text,p_ip inet,p_expires timestamptz
) RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE v_tenant_id uuid;
BEGIN
  IF NULLIF(pg_catalog.current_setting('app.user_id',true),'') IS DISTINCT FROM p_user_id::text THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE='42501';
  END IF;

  SELECT u.default_tenant_id INTO v_tenant_id
    FROM public.users AS u
    WHERE u.id=p_user_id AND u.status='active'
    FOR KEY SHARE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'forbidden' USING ERRCODE='42501';
  END IF;

  INSERT INTO public.refresh_tokens(id,user_id,family_id,token_hash,user_agent,ip,expires_at)
    VALUES(p_id,p_user_id,p_family_id,p_hash,p_user_agent,p_ip,p_expires);

  INSERT INTO public.audit_logs(id,tenant_id,actor_type,actor_id,action,entity,entity_id,diff)
    VALUES(pg_catalog.uuidv7(),v_tenant_id,'user',p_user_id,'auth.session.create',
      'refresh_token',p_id,'{}'::jsonb);
END $$;
-- +goose StatementEnd

-- +goose Down
-- Intentionally retain the identity guard when rolling back: restoring the prior
-- unscoped function would reintroduce account takeover.
