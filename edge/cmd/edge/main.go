package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/example/wafplatform/edge/internal/access"
	"github.com/example/wafplatform/edge/internal/configsync"
	"github.com/example/wafplatform/edge/internal/edgecore"
	"github.com/example/wafplatform/edge/internal/listener"
	"github.com/example/wafplatform/edge/internal/ratelimit"
	"github.com/example/wafplatform/edge/internal/response"
	"github.com/example/wafplatform/pkg/server"
	"github.com/example/wafplatform/pkg/wafcore"
	"gopkg.in/yaml.v3"
)

func main() {
	if err := run(); err != nil {
		log.Fatalf("edge gặp lỗi: %v", err)
	}
}

func run() error {
	snapshot, err := loadSnapshot()
	if err != nil {
		return fmt.Errorf("nạp snapshot edge: %w", err)
	}
	core := edgecore.New(&snapshot, "waf-edge")
	defer core.Close()
	if countryPath, asnPath := os.Getenv("EDGE_GEOIP_COUNTRY_MMDB"), os.Getenv("EDGE_GEOIP_ASN_MMDB"); countryPath != "" || asnPath != "" {
		geo, err := access.OpenMMDB(countryPath, asnPath)
		if err != nil {
			return fmt.Errorf("nạp cơ sở dữ liệu GeoIP/ASN: %w", err)
		}
		core.SetGeoResolver(geo)
		defer func() {
			if err := geo.Close(); err != nil {
				log.Printf("đóng cơ sở dữ liệu GeoIP/ASN: %v", err)
			}
		}()
	}
	if rawCIDRs := strings.TrimSpace(os.Getenv("EDGE_GLOBAL_BLOCKLIST_CIDRS")); rawCIDRs != "" {
		blocklist, err := access.NewPrefixTree(strings.Split(rawCIDRs, ","))
		if err != nil {
			return fmt.Errorf("nạp global blocklist CIDR: %w", err)
		}
		core.SetGlobalBlocklist(blocklist)
	}
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		backend, err := ratelimit.NewRedisClientBackend(redisURL)
		if err != nil {
			return fmt.Errorf("cấu hình Redis cho rate limit: %w", err)
		}
		syncer := ratelimit.NewAsyncRedisSync(backend, ratelimit.RedisSyncConfig{})
		core.SetRedisSync(syncer)
		defer func() {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := syncer.Close(ctx); err != nil {
				log.Printf("dừng đồng bộ counter Redis: %v", err)
			}
			if err := backend.Close(); err != nil {
				log.Printf("đóng kết nối Redis: %v", err)
			}
		}()
	}
	core.SetSecurityHeaders(response.SecurityHeaders{HSTS: envBool("EDGE_HSTS"), ContentTypeNosniff: envBool("EDGE_NOSNIFF"), FrameOptions: os.Getenv("EDGE_X_FRAME_OPTIONS"), ReferrerPolicy: os.Getenv("EDGE_REFERRER_POLICY"), RemoveServer: envBool("EDGE_REMOVE_SERVER")})
	metrics := metricsServer(core, server.Env("EDGE_METRICS_ADDR", "127.0.0.1:9090"))
	go serveMetrics(metrics)

	if tlsAddr := os.Getenv("EDGE_TLS_ADDR"); tlsAddr != "" {
		cache := listener.NewCertCache()
		if certDir := os.Getenv("EDGE_CERT_DIR"); certDir != "" {
			if err := loadCertificates(cache, certDir); err != nil {
				return fmt.Errorf("nạp chứng chỉ edge: %w", err)
			}
		} else if server.Env("EDGE_ENV", "development") == "production" {
			return fmt.Errorf("EDGE_CERT_DIR is required in production when TLS is enabled")
		}
		challenges, err := loadChallenges(os.Getenv("EDGE_ACME_CHALLENGE_FILE"))
		if err != nil {
			return fmt.Errorf("nạp token ACME: %w", err)
		}
		servers, err := listener.Start(listener.Config{
			HTTPAddr: server.Env("EDGE_HTTP_ADDR", ":8080"), TLSAddr: tlsAddr, Cache: cache,
			HTTPChallengeToken: func(token string) (string, bool) { value, ok := challenges[token]; return value, ok },
		}, core)
		if err != nil {
			return fmt.Errorf("khởi động listener edge: %w", err)
		}
		return shutdownOnSignal(func(ctx context.Context) error {
			return errors.Join(servers.Shutdown(ctx), metrics.Shutdown(ctx))
		}, core)
	}
	return serveHTTP(core, metrics, server.Env("EDGE_ADDR", ":8080"))
}

func envBool(name string) bool {
	value := strings.ToLower(strings.TrimSpace(os.Getenv(name)))
	return value == "1" || value == "true" || value == "yes"
}

func loadCertificates(cache *listener.CertCache, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	count := 0
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".crt" {
			continue
		}
		host := strings.TrimSuffix(entry.Name(), ".crt")
		cert, err := tls.LoadX509KeyPair(filepath.Join(dir, entry.Name()), filepath.Join(dir, host+".key"))
		if err != nil {
			return fmt.Errorf("load certificate %q: %w", host, err)
		}
		cache.Put(host, &cert)
		count++
	}
	if count == 0 {
		return fmt.Errorf("no .crt/.key certificate pairs found in %s", dir)
	}
	return nil
}
func loadChallenges(path string) (map[string]string, error) {
	out := map[string]string{}
	if path == "" {
		return out, nil
	}
	data, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // ACME challenge file is configured by the operator
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return out, nil
}

func loadSnapshot() (wafcore.Snapshot, error) {
	path := os.Getenv("EDGE_SNAPSHOT_FILE")
	if server.Env("EDGE_ENV", "development") == "production" && path == "" {
		return wafcore.Snapshot{}, fmt.Errorf("EDGE_SNAPSHOT_FILE is required in production")
	}
	if path == "" {
		return wafcore.Snapshot{}, nil
	}
	if server.Env("EDGE_ENV", "development") == "production" {
		keys, err := configsync.LoadPublicKeys()
		if err != nil {
			return wafcore.Snapshot{}, err
		}
		return configsync.LoadSignedFile(path, keys)
	}
	holder := configsync.New(nil, os.Getenv("EDGE_LAST_KNOWN_GOOD"))
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".yaml" || ext == ".yml" {
		if os.Getenv("EDGE_DEV_UNSIGNED") != "1" {
			return wafcore.Snapshot{}, fmt.Errorf("unsigned YAML snapshots require EDGE_DEV_UNSIGNED=1")
		}
		raw, err := os.ReadFile(filepath.Clean(path)) //nolint:gosec // snapshot path is configured by the operator
		if err != nil {
			return wafcore.Snapshot{}, err
		}
		var snapshot wafcore.Snapshot
		if err = yaml.Unmarshal(raw, &snapshot); err != nil {
			return wafcore.Snapshot{}, fmt.Errorf("decode YAML snapshot: %w", err)
		}
		if err = snapshot.Validate(); err != nil {
			return wafcore.Snapshot{}, err
		}
		jsonSnapshot, err := json.Marshal(snapshot)
		if err != nil {
			return wafcore.Snapshot{}, err
		}
		if err = holder.ApplyUnsignedLocalJSON(jsonSnapshot); err != nil {
			return wafcore.Snapshot{}, err
		}
		return *holder.Load(), nil
	}
	err := holder.LoadLocal(path)
	if err == nil {
		return *holder.Load(), nil
	}
	if os.Getenv("EDGE_DEV_UNSIGNED") != "1" {
		return wafcore.Snapshot{}, err
	}
	raw, readErr := os.ReadFile(filepath.Clean(path)) //nolint:gosec // snapshot path is configured by the operator
	if readErr != nil {
		return wafcore.Snapshot{}, readErr
	}
	if err = holder.ApplyUnsignedLocalJSON(raw); err != nil {
		return wafcore.Snapshot{}, err
	}
	return *holder.Load(), nil
}

func metricsServer(core *edgecore.Edge, addr string) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", core.Metrics())
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

func serveMetrics(srv *http.Server) {
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("metrics server gặp lỗi: %v", err)
	}
}

func serveHTTP(core *edgecore.Edge, metrics *http.Server, addr string) error {
	srv := &http.Server{Addr: addr, Handler: core, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 48 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	shutdownErr := make(chan error, 1)
	go func() {
		<-ctx.Done()
		core.SetReady(false)
		drain, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		shutdownErr <- errors.Join(srv.Shutdown(drain), metrics.Shutdown(drain))
	}()
	log.Printf("edge đang lắng nghe tại %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("edge server: %w", err)
	}
	return <-shutdownErr
}

func shutdownOnSignal(shutdown func(context.Context) error, core *edgecore.Edge) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	core.SetReady(false)
	drain, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	return shutdown(drain)
}
