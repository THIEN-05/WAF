package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/example/wafplatform/edge/internal/access"
	"github.com/example/wafplatform/edge/internal/bot"
	"github.com/example/wafplatform/edge/internal/configsync"
	"github.com/example/wafplatform/edge/internal/edgecore"
	"github.com/example/wafplatform/edge/internal/listener"
	"github.com/example/wafplatform/edge/internal/ratelimit"
	"github.com/example/wafplatform/edge/internal/response"
	"github.com/example/wafplatform/edge/internal/telemetry"
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
	syncCtx, cancelSync := context.WithCancel(context.Background())
	defer cancelSync()
	traceShutdown, traceErr := telemetry.InitTracing(syncCtx, os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if traceErr != nil {
		return fmt.Errorf("khởi tạo OpenTelemetry: %w", traceErr)
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := traceShutdown(shutdownCtx); err != nil {
			log.Printf("tắt OpenTelemetry: %q", err.Error())
		}
	}()
	cpURL := strings.TrimSpace(os.Getenv("EDGE_CONTROL_PLANE_URL"))
	snapshot, err := loadSnapshot()
	if err != nil && cpURL == "" {
		return fmt.Errorf("nạp snapshot edge: %w", err)
	}
	if err != nil {
		log.Printf("không nạp được snapshot cục bộ; thử last-known-good/CP: %q", err.Error())
		lastGood := strings.TrimSpace(os.Getenv("EDGE_LAST_KNOWN_GOOD"))
		if lastGood != "" {
			if keys, keyErr := configsync.LoadPublicKeys(); keyErr == nil {
				if saved, loadErr := configsync.LoadSignedFile(lastGood, keys); loadErr == nil {
					snapshot = saved
				} else {
					snapshot = wafcore.Snapshot{}
				}
			} else {
				snapshot = wafcore.Snapshot{}
			}
		} else {
			snapshot = wafcore.Snapshot{}
		}
	}
	core := edgecore.New(&snapshot, "waf-edge")
	defer core.Close()
	var logSink telemetry.BatchSink
	if ingestURL := strings.TrimSpace(os.Getenv("EDGE_INGEST_URL")); ingestURL != "" {
		logSink = telemetry.HTTPBatchSink{URL: ingestURL}
	} else {
		natsURL := server.Env("EDGE_NATS_URL", "nats://127.0.0.1:4222")
		sink, sinkErr := telemetry.NewNATSBatchSink(natsURL, server.Env("EDGE_NATS_LOG_SUBJECT", "edge.logs.v1"))
		if sinkErr != nil {
			return sinkErr
		}
		logSink = sink
	}
	shipper, shipErr := telemetry.NewShipper(logSink, telemetry.ShipperConfig{QueueSize: envInt("EDGE_LOG_QUEUE_SIZE", 4096), BatchSize: 1000, FlushInterval: time.Second, IPMaskV4Bits: envInt("EDGE_LOG_IP_MASK_V4_BITS", 24), IPMaskV6Bits: envInt("EDGE_LOG_IP_MASK_V6_BITS", 56), OnDropped: core.RecordLogDropped})
	if shipErr != nil {
		return fmt.Errorf("khởi tạo log shipper: %w", shipErr)
	}
	core.SetLogShipper(shipper)
	core.SetTelemetryIdentity(server.Env("EDGE_ID", ""), server.Env("REGION", ""))
	if closer, ok := logSink.(interface{ Close() }); ok {
		defer closer.Close()
	}
	defer shipper.Close()
	var siteCertCache *listener.CertCache
	if tlsAddr := strings.TrimSpace(os.Getenv("EDGE_TLS_ADDR")); tlsAddr != "" {
		siteCertCache = listener.NewCertCache()
		if certDir := os.Getenv("EDGE_CERT_DIR"); certDir != "" {
			if err := loadCertificates(siteCertCache, certDir); err != nil {
				return fmt.Errorf("nạp chứng chỉ edge: %w", err)
			}
		} else if cpURL == "" && server.Env("EDGE_ENV", "development") == "production" {
			return errors.New("EDGE_CERT_DIR or CP-provisioned TLS certificates are required in production")
		}
	}
	core.SetVerifiedBotResolver(bot.NewVerifiedResolver(net.DefaultResolver, []string{"googlebot.com", "search.msn.com", "duckduckgo.com"}, nil, 10*time.Minute))
	challengeKeys, err := loadChallengeKeyring()
	if err != nil {
		return fmt.Errorf("nạp keyring bot challenge: %w", err)
	}
	challengeEntitled := false
	for _, site := range snapshot.Sites {
		if site.Entitlements.BotJSChallenge {
			challengeEntitled = true
			break
		}
	}
	if challengeEntitled && challengeKeys == nil && cpURL == "" {
		return fmt.Errorf("bot JS challenge is entitled but EDGE_CHALLENGE_HMAC_KEYS is not configured")
	}
	if challengeKeys != nil {
		core.SetBotChallengeKeys(challengeKeys)
	}
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
	var cpAgent *configsync.Agent
	var cpSecrets *configsync.MemorySecrets
	var cpInstaller edgeSnapshotInstaller
	cpSecretsReady := false
	if cpURL != "" {
		token := strings.TrimSpace(os.Getenv("EDGE_REGISTRATION_TOKEN"))
		lastGood := strings.TrimSpace(os.Getenv("EDGE_LAST_KNOWN_GOOD"))
		if token == "" {
			return errors.New("EDGE_REGISTRATION_TOKEN is required with EDGE_CONTROL_PLANE_URL")
		}
		if lastGood == "" {
			return errors.New("EDGE_LAST_KNOWN_GOOD is required with EDGE_CONTROL_PLANE_URL")
		}
		keys, keyErr := configsync.LoadPublicKeys()
		if keyErr != nil {
			return keyErr
		}
		if len(keys) == 0 {
			return errors.New("signed CP snapshots require EDGE_PUBLIC_KEYS or EDGE_PUBLIC_KEYS_FILE")
		}
		client, clientErr := configsync.NewHTTPClient(cpURL, nil, 30*time.Second)
		if clientErr != nil {
			return clientErr
		}
		cpSecrets = configsync.NewMemorySecrets()
		if siteCertCache != nil {
			if err = cpSecrets.SetCertificateStore(siteCertCache); err != nil {
				return err
			}
		}
		cpInstaller = edgeSnapshotInstaller{core: core, secrets: cpSecrets}
		cpAgent, err = configsync.NewAgent(client, nil, cpInstaller, cpSecrets, configsync.AgentConfig{
			EdgeID: os.Getenv("EDGE_ID"), RegistrationToken: token, PublicKeys: keys, LastGoodPath: lastGood,
			OnSnapshotError:   func(err error) { log.Printf("config sync error: %q", err.Error()) },
			OnSnapshotStale:   func(age time.Duration) { log.Printf("config sync warning: stale snapshot age=%q", age) },
			OnSnapshotVersion: func(version uint64) { log.Printf("config sync applied snapshot version=%d", version) },
			OnSecrets:         cpInstaller.RefreshSecrets,
			HeartbeatValues: func() configsync.Heartbeat {
				var memory goruntime.MemStats
				goruntime.ReadMemStats(&memory)
				return configsync.Heartbeat{MemoryBytes: memory.Alloc}
			},
		})
		if err != nil {
			return err
		}
		if snapshot.Version > 0 {
			cpAgent.SetCurrentSnapshot(snapshot.Version, snapshot.GeneratedAt)
		}
		bootstrapCtx, cancel := context.WithTimeout(syncCtx, 10*time.Second)
		if err = cpAgent.Bootstrap(bootstrapCtx); err != nil {
			log.Printf("CP bootstrap unavailable; keep current snapshot and retry: error_type=%T", err)
		}
		cancel()
		if err == nil {
			cpSecretsReady = true
			if snapshot.Version > 0 {
				if installErr := cpInstaller.Apply(&snapshot); installErr != nil {
					return fmt.Errorf("install local signed snapshot with CP secrets: %w", installErr)
				}
			}
			pollCtx, cancel := context.WithTimeout(syncCtx, 10*time.Second)
			if pollErr := cpAgent.SyncOnce(pollCtx); pollErr != nil {
				log.Printf("initial CP snapshot fetch failed; keep current snapshot: error_type=%T", pollErr)
			}
			cancel()
		}
		go func() {
			if runErr := cpAgent.Run(syncCtx); runErr != nil && syncCtx.Err() == nil {
				log.Printf("config sync stopped: error_type=%T", runErr)
			}
		}()
	}
	if challengeEntitled && challengeKeys == nil && !cpSecretsReady {
		return errors.New("challenge-enabled local snapshot requires CP-provisioned secrets or EDGE_CHALLENGE_HMAC_KEYS")
	}
	core.SetReady(false)
	if err := core.SelfTest(); err != nil {
		return fmt.Errorf("edge startup self-test: %w", err)
	}
	core.SetReady(true)
	core.SetSecurityHeaders(response.SecurityHeaders{HSTS: envBool("EDGE_HSTS"), ContentTypeNosniff: envBool("EDGE_NOSNIFF"), FrameOptions: os.Getenv("EDGE_X_FRAME_OPTIONS"), ReferrerPolicy: os.Getenv("EDGE_REFERRER_POLICY"), RemoveServer: envBool("EDGE_REMOVE_SERVER")})
	metrics := metricsServer(core, cpAgent, server.Env("EDGE_METRICS_ADDR", "127.0.0.1:9090"))
	go serveMetrics(metrics)

	if tlsAddr := os.Getenv("EDGE_TLS_ADDR"); tlsAddr != "" {
		cache := siteCertCache
		if cpSecrets != nil {
			if err := cpSecrets.InstallCertificates(cache); err != nil {
				return fmt.Errorf("install CP TLS certificates: %w", err)
			}
			if server.Env("EDGE_ENV", "development") == "production" && cpSecrets.CertificateCount() == 0 && os.Getenv("EDGE_CERT_DIR") == "" {
				return errors.New("CP did not provision any site TLS certificate")
			}
		}
		challenges, err := loadChallenges(os.Getenv("EDGE_ACME_CHALLENGE_FILE"))
		if err != nil {
			return fmt.Errorf("nạp token ACME: %w", err)
		}
		challengeTokens, err := configsync.NewChallengeTokens(challenges)
		if err != nil {
			return fmt.Errorf("ACME token store: %w", err)
		}
		servers, err := listener.Start(listener.Config{
			HTTPAddr: server.Env("EDGE_HTTP_ADDR", ":8080"), TLSAddr: tlsAddr, Cache: cache,
			HTTPChallengeToken: challengeTokens.Lookup,
			CanonicalHTTPHost:  core.CanonicalHTTPHost,
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

// loadChallengeKeyring reads externally provisioned secrets; key bytes never enter snapshots or logs.
func loadChallengeKeyring() (bot.KeyRing, error) {
	raw := strings.TrimSpace(os.Getenv("EDGE_CHALLENGE_HMAC_KEYS"))
	if raw == "" {
		return nil, nil
	}
	if len(raw) > 16<<10 {
		return nil, fmt.Errorf("challenge keyring exceeds 16 KiB")
	}
	keys := map[string][]byte{}
	for _, entry := range strings.Split(raw, ",") {
		id, value, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok || id == "" || len(id) > 64 || strings.ContainsAny(id, " /\\\t\r\n") || value == "" {
			return nil, fmt.Errorf("expected comma-separated key_id=base64 values")
		}
		if len(keys) >= 16 {
			return nil, fmt.Errorf("at most 16 challenge keys are allowed")
		}
		decoded, err := base64.RawStdEncoding.DecodeString(value)
		if err != nil {
			decoded, err = base64.StdEncoding.DecodeString(value)
		}
		if err != nil || len(decoded) < 32 {
			return nil, fmt.Errorf("challenge key %q must be valid base64 with at least 32 decoded bytes", id)
		}
		if _, exists := keys[id]; exists {
			return nil, fmt.Errorf("duplicate challenge key id %q", id)
		}
		keys[id] = decoded
	}
	active := strings.TrimSpace(os.Getenv("EDGE_CHALLENGE_HMAC_ACTIVE_KEY_ID"))
	if active == "" && len(keys) == 1 {
		for id := range keys {
			active = id
		}
	}
	if _, ok := keys[active]; !ok {
		return nil, fmt.Errorf("EDGE_CHALLENGE_HMAC_ACTIVE_KEY_ID must name a configured key")
	}
	return bot.StaticKeyRing{Active: active, Keys: keys}, nil
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
	cpConfigured := strings.TrimSpace(os.Getenv("EDGE_CONTROL_PLANE_URL")) != ""
	if server.Env("EDGE_ENV", "development") == "production" && path == "" && !cpConfigured {
		return wafcore.Snapshot{}, fmt.Errorf("EDGE_SNAPSHOT_FILE or EDGE_CONTROL_PLANE_URL is required in production")
	}
	if path == "" && cpConfigured {
		lastGood := strings.TrimSpace(os.Getenv("EDGE_LAST_KNOWN_GOOD"))
		if lastGood == "" {
			if server.Env("EDGE_ENV", "development") == "production" {
				return wafcore.Snapshot{}, errors.New("EDGE_LAST_KNOWN_GOOD is required for CP-managed production edge")
			}
			return wafcore.Snapshot{}, nil
		}
		keys, err := configsync.LoadPublicKeys()
		if err != nil {
			return wafcore.Snapshot{}, err
		}
		snapshot, err := configsync.LoadSignedFile(lastGood, keys)
		if errors.Is(err, os.ErrNotExist) {
			return wafcore.Snapshot{}, nil
		}
		return snapshot, err
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

func metricsServer(core *edgecore.Edge, agent *configsync.Agent, addr string) *http.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		if agent != nil {
			status := agent.Status()
			core.RefreshMetrics(status.Version, status.Age, true, agent.SnapshotStale(), agent.CertificateExpiry())
		} else {
			core.RefreshMetrics(0, 0, false, false, time.Time{})
		}
		core.Metrics().ServeHTTP(w, r)
	})
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}

func envInt(name string, fallback int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < 0 {
		return fallback
	}
	return parsed
}

type edgeSnapshotInstaller struct {
	core    *edgecore.Edge
	secrets *configsync.MemorySecrets
}

func (i edgeSnapshotInstaller) Apply(snapshot *wafcore.Snapshot) error {
	if i.core == nil || snapshot == nil {
		return errors.New("nil edge snapshot installer input")
	}
	if err := i.applyChallengeKeys(snapshot); err != nil {
		return err
	}
	return i.core.Apply(snapshot)
}

func (i edgeSnapshotInstaller) RefreshSecrets() error {
	if i.core == nil {
		return errors.New("nil edge for secret refresh")
	}
	snapshot := i.core.Snapshot()
	if snapshot == nil {
		return nil
	}
	return i.applyChallengeKeys(snapshot)
}

func (i edgeSnapshotInstaller) applyChallengeKeys(snapshot *wafcore.Snapshot) error {
	if i.secrets == nil {
		return errors.New("edge secret store is unavailable")
	}
	keys := make(map[string][]byte)
	active := ""
	for _, site := range snapshot.Sites {
		if !site.Entitlements.BotJSChallenge {
			continue
		}
		id := site.Secrets.ChallengeHMACKeyID
		key, ok := i.secrets.Secret(id)
		if !ok || len(key) < 32 {
			return fmt.Errorf("snapshot challenge key %q was not provisioned over mTLS", id)
		}
		keys[id] = key
		if active == "" {
			active = id
		}
	}
	i.core.SetBotChallengeKeys(bot.StaticKeyRing{Active: active, Keys: keys})
	return nil
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
