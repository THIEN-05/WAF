package analytics

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

type AnalyticsService struct {
	Pool         *pgxpool.Pool
	Cache        redis.UniversalClient
	ClickHouse   ClickHouseHTTP
	QueryTimeout time.Duration
	CacheTTL     time.Duration
	Now          func() time.Time
}

type QueryResult struct {
	Rows []json.RawMessage `json:"rows"`
}

func (s AnalyticsService) Query(ctx context.Context, tenantID, siteID uuid.UUID, kind string, from, to time.Time, limit int) (QueryResult, error) {
	if s.Pool == nil || tenantID == uuid.Nil || siteID == uuid.Nil {
		return QueryResult{}, errors.New("analytics identity is required")
	}
	if kind != "overview" && kind != "timeseries" && kind != "top" {
		return QueryResult{}, errors.New("unsupported analytics view")
	}
	var retention int
	err := s.Pool.QueryRow(ctx, `SELECT coalesce((p.entitlements->'limits'->>'log_retention_days')::int,0)
  FROM public.sites s JOIN public.subscriptions sub ON sub.tenant_id=s.tenant_id AND sub.status='active'
  JOIN public.plans p ON p.id=sub.plan_id
  WHERE s.id=$1 AND s.tenant_id=$2 AND s.deleted_at IS NULL ORDER BY sub.created_at DESC LIMIT 1`, siteID, tenantID).Scan(&retention)
	if errors.Is(err, pgx.ErrNoRows) {
		return QueryResult{}, errors.New("analytics site not found")
	}
	if err != nil {
		return QueryResult{}, fmt.Errorf("authorize analytics site: %w", err)
	}
	now := time.Now
	if s.Now != nil {
		now = s.Now
	}
	if to.IsZero() {
		to = now().UTC()
	}
	if from.IsZero() {
		from = to.Add(-time.Hour)
	}
	if retention < 1 || to.After(now().Add(time.Minute)) || !from.Before(to) || from.Before(to.Add(-time.Duration(retention)*24*time.Hour)) {
		return QueryResult{}, errors.New("analytics range exceeds plan retention")
	}
	if limit < 1 {
		limit = 100
	}
	if limit > 500 {
		limit = 500
	}
	cacheKey := fmt.Sprintf("analytics:v1:%s:%s:%s:%d:%d:%d", tenantID, siteID, kind, from.UnixMilli(), to.UnixMilli(), limit)
	if s.Cache != nil {
		if cached, cacheErr := s.Cache.Get(ctx, cacheKey).Bytes(); cacheErr == nil {
			var result QueryResult
			if json.Unmarshal(cached, &result) == nil {
				return result, nil
			}
		}
	}
	query, err := analyticsSQL(kind, limit)
	if err != nil {
		return QueryResult{}, err
	}
	timeout := s.QueryTimeout
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	params := url.Values{"param_tenant_id": {tenantID.String()}, "param_site_id": {siteID.String()}, "param_from": {from.UTC().Format(time.RFC3339Nano)}, "param_to": {to.UTC().Format(time.RFC3339Nano)}, "param_limit": {strconv.Itoa(limit)}}
	body, err := s.ClickHouse.query(queryCtx, query, params)
	if err != nil {
		return QueryResult{}, err
	}
	result := QueryResult{Rows: make([]json.RawMessage, 0)}
	decoder := json.NewDecoder(strings.NewReader(string(body)))
	for {
		var row json.RawMessage
		if err = decoder.Decode(&row); err == io.EOF {
			break
		}
		if err != nil {
			return QueryResult{}, fmt.Errorf("decode analytics result: %w", err)
		}
		result.Rows = append(result.Rows, row)
	}
	if s.Cache != nil {
		if encoded, marshalErr := json.Marshal(result); marshalErr == nil {
			ttl := s.CacheTTL
			if ttl <= 0 {
				ttl = 20 * time.Second
			}
			_ = s.Cache.Set(ctx, cacheKey, encoded, ttl).Err()
		}
	}
	return result, nil
}

func analyticsSQL(kind string, limit int) (string, error) {
	whereEvents := `tenant_id={tenant_id:UUID} AND site_id={site_id:UUID} AND ts >= {from:DateTime64(3)} AND ts < {to:DateTime64(3)}`
	whereStats := `tenant_id={tenant_id:UUID} AND site_id={site_id:UUID} AND minute >= toStartOfMinute({from:DateTime64(3)}) AND minute < {to:DateTime64(3)}`
	switch kind {
	case "overview":
		return `SELECT sum(requests) requests,sum(blocked) blocked,sum(challenged) challenged,sum(rate_limited) rate_limited,sum(cache_hits) cache_hits,sum(status_5xx) status_5xx FROM site_stats_1m WHERE ` + whereStats, nil
	case "timeseries":
		return `SELECT minute,sum(requests) requests,sum(blocked) blocked,sum(challenged) challenged,sum(rate_limited) rate_limited,sum(cache_hits) cache_hits,sum(bytes_out) bytes_out,sum(status_5xx) status_5xx FROM site_stats_1m WHERE ` + whereStats + ` GROUP BY minute ORDER BY minute LIMIT {limit:UInt32}`, nil
	case "top":
		return fmt.Sprintf(`SELECT rule_id,count() hits FROM security_events WHERE %s GROUP BY rule_id ORDER BY hits DESC,rule_id LIMIT {limit:UInt32}`, whereEvents), nil
	default:
		return "", errors.New("unsupported analytics view")
	}
}

func (c ClickHouseHTTP) query(ctx context.Context, sql string, params url.Values) ([]byte, error) {
	base, err := url.Parse(c.Endpoint)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return nil, errors.New("invalid ClickHouse endpoint")
	}
	query := base.Query()
	query.Set("database", c.Database)
	query.Set("query", sql+" FORMAT JSONEachRow")
	for key, values := range params {
		for _, value := range values {
			query.Set(key, value)
		}
	}
	base.RawQuery = query.Encode()
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 4 * time.Second}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return nil, err
	}
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("ClickHouse query: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 2<<20 {
		return nil, errors.New("analytics result exceeds size limit")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("ClickHouse query rejected (status %d)", resp.StatusCode)
	}
	return body, nil
}
