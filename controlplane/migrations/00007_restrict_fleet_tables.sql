-- +goose Up
-- Fleet state is an internal control-plane concern. The public API role must not
-- inspect or mutate bootstrap credentials, edge identities, or revocation state.
REVOKE ALL PRIVILEGES ON TABLE
  public.edges,
  public.edge_certificates,
  public.edge_bootstrap_tokens,
  public.certificate_issuance_rate_limits,
  public.edge_dns_withdrawal_limits
FROM PUBLIC, waf_api, waf_worker;

GRANT SELECT, INSERT, UPDATE ON TABLE
  public.edges,
  public.edge_bootstrap_tokens,
  public.edge_certificates
TO waf_worker;
GRANT SELECT, INSERT, UPDATE ON TABLE
  public.certificate_issuance_rate_limits,
  public.edge_dns_withdrawal_limits
TO waf_worker;

-- +goose Down
REVOKE ALL PRIVILEGES ON TABLE
  public.edges,
  public.edge_certificates,
  public.edge_bootstrap_tokens,
  public.certificate_issuance_rate_limits,
  public.edge_dns_withdrawal_limits
FROM waf_worker;
GRANT SELECT, INSERT, UPDATE ON TABLE
  public.edges,
  public.edge_bootstrap_tokens,
  public.edge_certificates
TO waf_api, waf_worker;
GRANT SELECT, INSERT, UPDATE, DELETE ON TABLE
  public.certificate_issuance_rate_limits,
  public.edge_dns_withdrawal_limits
TO waf_worker;
