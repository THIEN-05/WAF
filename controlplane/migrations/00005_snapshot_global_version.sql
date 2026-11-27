-- +goose Up
CREATE SEQUENCE config_snapshot_global_version_seq AS bigint;
SELECT setval(
  'config_snapshot_global_version_seq',
  GREATEST(COALESCE((SELECT max(version) FROM config_snapshots), 0), 1),
  EXISTS (SELECT 1 FROM config_snapshots)
);
GRANT USAGE, SELECT ON SEQUENCE config_snapshot_global_version_seq TO waf_worker;

-- +goose Down
DROP SEQUENCE config_snapshot_global_version_seq;
