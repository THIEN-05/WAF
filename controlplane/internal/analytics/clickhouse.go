package analytics

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type BatchWriter interface {
	Write(context.Context, Rows) error
}

type PartialWriteError struct {
	Failed Rows
	Cause  error
}

func (e *PartialWriteError) Error() string { return e.Cause.Error() }
func (e *PartialWriteError) Unwrap() error { return e.Cause }

type ClickHouseHTTP struct {
	Endpoint, Database, Username, Password string
	Client                                 *http.Client
}

type eventInsert struct {
	TS            string `json:"ts"`
	TenantID      string `json:"tenant_id"`
	SiteID        string `json:"site_id"`
	EdgeID        string `json:"edge_id"`
	Region        string `json:"region"`
	ClientIP      string `json:"client_ip"`
	Country       string `json:"country"`
	ASN           uint32 `json:"asn"`
	Method        string `json:"method"`
	Host          string `json:"host"`
	Path          string `json:"path"`
	Status        uint16 `json:"status"`
	Action        string `json:"action"`
	RuleID        string `json:"rule_id"`
	WAFScore      uint16 `json:"waf_score"`
	BotScore      uint8  `json:"bot_score"`
	LatencyMS     uint32 `json:"latency_ms"`
	RetentionDays uint16 `json:"retention_days"`
}

type statsInsert struct {
	Minute      string `json:"minute"`
	TenantID    string `json:"tenant_id"`
	SiteID      string `json:"site_id"`
	Requests    uint64 `json:"requests"`
	Blocked     uint64 `json:"blocked"`
	Challenged  uint64 `json:"challenged"`
	RateLimited uint64 `json:"rate_limited"`
	CacheHits   uint64 `json:"cache_hits"`
	BytesOut    uint64 `json:"bytes_out"`
	Status5xx   uint64 `json:"status_5xx"`
}

func clickHouseTimestamp(value time.Time, precision string) string {
	return value.UTC().Format(precision)
}

func (c ClickHouseHTTP) Write(ctx context.Context, rows Rows) error {
	if strings.TrimSpace(c.Endpoint) == "" {
		return errors.New("ClickHouse endpoint is required")
	}
	client := c.Client
	if client == nil {
		client = &http.Client{Timeout: 8 * time.Second}
	}
	if len(rows.Events) > 0 {
		var body bytes.Buffer
		enc := json.NewEncoder(&body)
		for _, row := range rows.Events {
			e := row.Event
			ip := net.ParseIP(e.ClientIP)
			ip6 := "::"
			if ip != nil {
				if ip.To4() != nil {
					ip6 = "::ffff:" + ip.String()
				} else {
					ip6 = ip.String()
				}
			}
			if err := enc.Encode(eventInsert{TS: clickHouseTimestamp(e.TS, "2006-01-02 15:04:05.000"), TenantID: e.TenantID, SiteID: e.SiteID, EdgeID: e.EdgeID, Region: e.Region, ClientIP: ip6, Country: e.Country, ASN: e.ASN, Method: e.Method, Host: e.Host, Path: e.Path, Status: e.Status, Action: e.Action, RuleID: e.RuleID, WAFScore: e.WAFScore, BotScore: e.BotScore, LatencyMS: e.LatencyMS, RetentionDays: row.RetentionDays}); err != nil {
				return err
			}
		}
		if err := c.insert(ctx, client, "INSERT INTO security_events FORMAT JSONEachRow", body.Bytes()); err != nil {
			return err
		}
	}
	if len(rows.Stats) > 0 {
		var body bytes.Buffer
		enc := json.NewEncoder(&body)
		for _, stats := range rows.Stats {
			if err := enc.Encode(statsInsert{Minute: clickHouseTimestamp(stats.Minute, "2006-01-02 15:04:05"), TenantID: stats.TenantID, SiteID: stats.SiteID, Requests: stats.Requests, Blocked: stats.Blocked, Challenged: stats.Challenged, RateLimited: stats.RateLimited, CacheHits: stats.CacheHits, BytesOut: stats.BytesOut, Status5xx: stats.Status5xx}); err != nil {
				return err
			}
		}
		if err := c.insert(ctx, client, "INSERT INTO site_stats_1m FORMAT JSONEachRow", body.Bytes()); err != nil {
			return &PartialWriteError{Failed: Rows{Stats: rows.Stats}, Cause: err}
		}
	}
	return nil
}

func (c ClickHouseHTTP) insert(ctx context.Context, client *http.Client, statement string, body []byte) (retErr error) {
	base, err := url.Parse(c.Endpoint)
	if err != nil || (base.Scheme != "http" && base.Scheme != "https") || base.Host == "" {
		return errors.New("invalid ClickHouse endpoint")
	}
	query := url.Values{}
	query.Set("database", c.Database)
	query.Set("query", statement)
	base.RawQuery = query.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base.String(), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	if c.Username != "" {
		req.SetBasicAuth(c.Username, c.Password)
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("ClickHouse insert: %w", err)
	}
	defer func() { retErr = errors.Join(retErr, resp.Body.Close()) }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		message, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("ClickHouse insert rejected (status %d): %s", resp.StatusCode, strings.TrimSpace(string(message)))
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return nil
}
