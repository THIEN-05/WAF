//go:build integration

package analytics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/example/wafplatform/pkg/wafcore"
	"github.com/google/uuid"
)

func TestClickHouseBatchRetentionAndTenantPredicatesIntegration(t *testing.T) {
	endpoint := os.Getenv("CLICKHOUSE_URL")
	if endpoint == "" {
		if os.Getenv("CLICKHOUSE_INTEGRATION_REQUIRED") == "1" {
			t.Fatal("ClickHouse integration is required but CLICKHOUSE_URL is unset")
		}
		t.Skip("requires real ClickHouse; set CLICKHOUSE_URL")
	}
	client := ClickHouseHTTP{Endpoint: endpoint, Database: envValue("CLICKHOUSE_DATABASE", "waf"), Username: os.Getenv("CLICKHOUSE_USER"), Password: os.Getenv("CLICKHOUSE_PASSWORD")}
	schema, err := os.ReadFile("../../clickhouse/schema.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range strings.Split(string(schema), ";") {
		statement = strings.TrimSpace(statement)
		if statement == "" {
			continue
		}
		if err = clickHouseExec(t, client, statement); err != nil {
			t.Fatalf("create ClickHouse schema: %v", err)
		}
	}
	tenantA, tenantB, siteA := uuid.NewString(), uuid.NewString(), uuid.NewString()
	now := time.Now().UTC().Truncate(time.Millisecond)
	rows := Rows{Events: []EventRow{
		{Event: wafcore.LogEvent{TS: now, SiteID: siteA, TenantID: tenantA, EdgeID: "integration", Region: "test", ClientIP: "192.0.2.14", Method: "GET", Host: "a.example.test", Path: "/", Status: 200, Action: "allow"}, RetentionDays: 7},
		{Event: wafcore.LogEvent{TS: now, SiteID: uuid.NewString(), TenantID: tenantB, EdgeID: "integration", Region: "test", ClientIP: "2001:db8::14", Method: "GET", Host: "b.example.test", Path: "/", Status: 403, Action: "block"}, RetentionDays: 30},
	}, Stats: []wafcore.SiteStats1m{{Minute: now.Truncate(time.Minute), TenantID: tenantA, SiteID: siteA, Requests: 2}}}
	started := time.Now()
	if err = client.Write(context.Background(), rows); err != nil {
		t.Fatal(err)
	}
	t.Logf("clickhouse integration batch events=%d stats=%d elapsed=%s", len(rows.Events), len(rows.Stats), time.Since(started))
	params := url.Values{"param_tenant_id": {tenantA}, "param_site_id": {siteA}, "param_from": {clickHouseTimestamp(now.Add(-time.Minute), "2006-01-02 15:04:05.000")}, "param_to": {clickHouseTimestamp(now.Add(time.Minute), "2006-01-02 15:04:05.000")}}
	result, err := client.query(context.Background(), `SELECT count() count,any(retention_days) retention_days FROM security_events WHERE tenant_id={tenant_id:UUID} AND site_id={site_id:UUID} AND ts >= {from:DateTime64(3)} AND ts < {to:DateTime64(3)}`, params)
	if err != nil {
		t.Fatal(err)
	}
	var actual struct {
		Count     json.RawMessage `json:"count"`
		Retention uint16          `json:"retention_days"`
	}
	if err = json.Unmarshal(result, &actual); err != nil {
		t.Fatal(err)
	}
	countText := strings.Trim(string(actual.Count), `"`)
	count, parseErr := strconv.ParseUint(countText, 10, 64)
	if parseErr != nil {
		t.Fatalf("parse ClickHouse UInt64 count %s: %v", actual.Count, parseErr)
	}
	if count != 1 || actual.Retention != 7 {
		t.Fatalf("tenant-scoped rows=%d retention=%d, want 1/7", count, actual.Retention)
	}
	bad := Rows{Events: []EventRow{{Event: wafcore.LogEvent{TS: now, TenantID: "not-a-uuid", SiteID: siteA}, RetentionDays: 7}}}
	if err = client.Write(context.Background(), bad); err == nil {
		t.Fatal("ClickHouse accepted malformed-identity batch")
	}
}

func clickHouseExec(t testing.TB, client ClickHouseHTTP, statement string) error {
	t.Helper()
	endpoint, err := url.Parse(client.Endpoint)
	if err != nil {
		return err
	}
	query := endpoint.Query()
	query.Set("database", client.Database)
	query.Set("query", statement)
	endpoint.RawQuery = query.Encode()
	req, err := http.NewRequest(http.MethodPost, endpoint.String(), nil)
	if err != nil {
		return err
	}
	if client.Username != "" {
		req.SetBasicAuth(client.Username, client.Password)
	}
	transport := client.Client
	if transport == nil {
		transport = http.DefaultClient
	}
	resp, err := transport.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return nil
}

func BenchmarkClickHouseWriteBatchIntegration(b *testing.B) {
	endpoint := os.Getenv("CLICKHOUSE_URL")
	if endpoint == "" {
		b.Skip("requires ClickHouse; set CLICKHOUSE_URL")
	}
	client := ClickHouseHTTP{Endpoint: endpoint, Database: envValue("CLICKHOUSE_DATABASE", "waf"), Username: os.Getenv("CLICKHOUSE_USER"), Password: os.Getenv("CLICKHOUSE_PASSWORD")}
	schema, err := os.ReadFile("../../clickhouse/schema.sql")
	if err != nil {
		b.Fatal(err)
	}
	for _, statement := range strings.Split(string(schema), ";") {
		statement = strings.TrimSpace(statement)
		if statement != "" {
			if err = clickHouseExec(b, client, statement); err != nil {
				b.Fatal(err)
			}
		}
	}
	rows := Rows{Events: make([]EventRow, 1000)}
	now := time.Now().UTC().Truncate(time.Millisecond)
	for i := range rows.Events {
		rows.Events[i] = EventRow{Event: wafcore.LogEvent{TS: now, RequestID: uuid.NewString(), SiteID: uuid.NewString(), TenantID: uuid.NewString(), EdgeID: "benchmark", Region: "bench", ClientIP: "192.0.2.10", Method: "GET", Host: "bench.example.test", Path: "/", Status: 200, Action: "allow"}, RetentionDays: 7}
	}
	encoded, _ := json.Marshal(rows.Events)
	b.SetBytes(int64(len(encoded)))
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err = client.Write(context.Background(), rows); err != nil {
			b.Fatal(err)
		}
	}
}

func envValue(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
