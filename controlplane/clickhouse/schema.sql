CREATE TABLE IF NOT EXISTS waf.security_events (
  ts DateTime64(3), tenant_id UUID, site_id UUID, edge_id String,
  region LowCardinality(String), client_ip IPv6, country LowCardinality(String),
  asn UInt32, method LowCardinality(String), host String, path String,
  status UInt16, action LowCardinality(String), rule_id String,
  waf_score UInt16, bot_score UInt8, latency_ms UInt32, retention_days UInt16
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, site_id, ts)
TTL toDateTime(ts) + toIntervalDay(retention_days);

CREATE TABLE IF NOT EXISTS waf.site_stats_1m (
  minute DateTime, tenant_id UUID, site_id UUID,
  requests UInt64, blocked UInt64, challenged UInt64, rate_limited UInt64,
  cache_hits UInt64, bytes_out UInt64, status_5xx UInt64
) ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (tenant_id, site_id, minute);
