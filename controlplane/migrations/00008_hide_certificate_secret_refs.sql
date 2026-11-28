-- +goose Up
-- Certificate secret references identify private material in the worker SecretStore.
-- The public API currently has no certificate read endpoint; keep it unable to read
-- any certificate rows while retaining its existing write grants and tenant RLS.
REVOKE SELECT ON TABLE public.certificates FROM PUBLIC, waf_api;

-- +goose Down
GRANT SELECT ON TABLE public.certificates TO waf_api;
