package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/example/wafplatform/edge/internal/configsync"
	"github.com/example/wafplatform/edge/internal/edgecore"
	"github.com/example/wafplatform/edge/internal/listener"
	"github.com/example/wafplatform/edge/internal/response"
	"github.com/example/wafplatform/pkg/server"
	"github.com/example/wafplatform/pkg/wafcore"
	"gopkg.in/yaml.v3"
)

func main() {
	snapshot, err := loadSnapshot()
	if err != nil {
		log.Fatalf("nạp snapshot edge: %v", err)
	}
	core := edgecore.New(&snapshot, "waf-edge")
	core.SetSecurityHeaders(response.SecurityHeaders{HSTS: envBool("EDGE_HSTS"), ContentTypeNosniff: envBool("EDGE_NOSNIFF"), FrameOptions: os.Getenv("EDGE_X_FRAME_OPTIONS"), ReferrerPolicy: os.Getenv("EDGE_REFERRER_POLICY"), RemoveServer: envBool("EDGE_REMOVE_SERVER")})
	metrics := metricsServer(core, server.Env("EDGE_METRICS_ADDR", "127.0.0.1:9090"))
	go serveMetrics(metrics)

	if tlsAddr := os.Getenv("EDGE_TLS_ADDR"); tlsAddr != "" {
		cache := listener.NewCertCache()
		if certDir := os.Getenv("EDGE_CERT_DIR"); certDir != "" {
			if err := loadCertificates(cache, certDir); err != nil {
				log.Fatalf("nạp chứng chỉ edge: %v", err)
			}
		} else if server.Env("EDGE_ENV", "development") == "production" {
			log.Fatal("EDGE_CERT_DIR is required in production when TLS is enabled")
		}
		challenges, err := loadChallenges(os.Getenv("EDGE_ACME_CHALLENGE_FILE"))
		if err != nil {
			log.Fatalf("nạp token ACME: %v", err)
		}
		servers, err := listener.Start(listener.Config{
			HTTPAddr: server.Env("EDGE_HTTP_ADDR", ":8080"), TLSAddr: tlsAddr, Cache: cache,
			HTTPChallengeToken: func(token string) (string, bool) { value, ok := challenges[token]; return value, ok },
		}, core)
		if err != nil {
			log.Fatalf("khởi động listener edge: %v", err)
		}
		shutdownOnSignal(func(ctx context.Context) { _ = servers.Shutdown(ctx); _ = metrics.Shutdown(ctx); core.Close() }, core)
		return
	}
	serveHTTP(core, metrics, server.Env("EDGE_ADDR", ":8080"))
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
	data, err := os.ReadFile(path)
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
		raw, err := os.ReadFile(path)
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
	raw, readErr := os.ReadFile(path)
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

func serveHTTP(core *edgecore.Edge, metrics *http.Server, addr string) {
	srv := &http.Server{Addr: addr, Handler: core, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 90 * time.Second, MaxHeaderBytes: 48 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-ctx.Done()
		core.SetReady(false)
		drain, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = srv.Shutdown(drain)
		_ = metrics.Shutdown(drain)
		core.Close()
	}()
	log.Printf("edge đang lắng nghe tại %s", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("edge server gặp lỗi: %v", err)
	}
}

func shutdownOnSignal(shutdown func(context.Context), core *edgecore.Edge) {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	<-ctx.Done()
	core.SetReady(false)
	drain, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	shutdown(drain)
}
