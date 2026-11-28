//go:build integration

package integration

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/example/wafplatform/controlplane/internal/certs"
	"github.com/google/uuid"
)

func TestCertificateSecretReferenceIsNotReadableOrPublicIntegration(t *testing.T) {
	ctx, admin, redisClient := integrationDeps(t)
	cleanup := cleanupForTest(t, admin, redisClient)
	apiPool := apiRolePool(t, ctx, admin, mustDatabaseURL(t), cleanup)
	if _, err := apiPool.Exec(ctx, `SELECT secret_ref FROM public.certificates LIMIT 0`); err == nil {
		t.Fatal("waf_api can read certificates.secret_ref")
	} else if !isPermissionDenied(err) {
		t.Fatalf("reading certificates.secret_ref failed for unexpected reason: %v", err)
	}

	// This explicit inventory is intentionally empty: no secret, token, hash, key, or
	// serial column is approved for direct reads by the public API role.
	allowed := map[string]string{}
	rows, err := admin.Query(ctx, `SELECT table_name,column_name
  FROM information_schema.columns
  WHERE table_schema='public'
    AND column_name ~* '(hash|token|secret|serial|key)'
    AND has_column_privilege('waf_api',format('public.%I',table_name),column_name,'SELECT')
  ORDER BY table_name,column_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var table, column string
		if err = rows.Scan(&table, &column); err != nil {
			t.Fatal(err)
		}
		name := table + "." + column
		if _, ok := allowed[name]; !ok {
			t.Errorf("sensitive column remains readable by waf_api without an approved reason: %s", name)
		}
	}
	if err = rows.Err(); err != nil {
		t.Fatal(err)
	}

	statusJSON, err := json.Marshal(certs.Status(uuid.Nil, time.Time{}, time.Time{}))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(statusJSON, []byte("secret_ref")) {
		t.Fatalf("public certificate status contains secret_ref: %s", statusJSON)
	}

}
