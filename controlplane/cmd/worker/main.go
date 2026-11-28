package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
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

	"github.com/example/wafplatform/controlplane/internal/platform/db"
	platformnats "github.com/example/wafplatform/controlplane/internal/platform/nats"
	"github.com/example/wafplatform/controlplane/internal/platform/secret"
	"github.com/example/wafplatform/controlplane/internal/snapshot"
)

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("worker stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	databaseURL := os.Getenv("WORKER_DATABASE_URL")
	if databaseURL == "" {
		databaseURL = os.Getenv("DATABASE_URL")
	}
	if databaseURL == "" {
		return errors.New("WORKER_DATABASE_URL is required")
	}
	pool, err := db.OpenWorker(ctx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	nc, err := platformnats.Connect(env("NATS_URL", "nats://127.0.0.1:4222"))
	if err != nil {
		return fmt.Errorf("connect NATS: %w", err)
	}
	defer nc.Close()
	keyID := env("SNAPSHOT_SIGNING_KEY_ID", "cp-1")
	private, err := privateKey(os.Getenv("SNAPSHOT_SIGNING_PRIVATE_KEY"))
	if err != nil {
		return err
	}
	secrets := secret.NewMemory()
	if err = secrets.Put(ctx, "snapshot-signing/"+keyID, private); err != nil {
		return err
	}
	objects := snapshot.FileObjects{Root: env("SNAPSHOT_OBJECTS_DIR", "var/snapshots")}
	region := env("SNAPSHOT_REGION", "local")
	repository := snapshot.PostgresRepository{Pool: pool.Pool}
	builder := &snapshot.Builder{
		Repository: repository,
		Objects:    objects,
		Signer:     snapshot.SecretSigner{Store: secrets, KeyID: keyID},
		PublicKeys: map[string]ed25519.PublicKey{keyID: private.Public().(ed25519.PublicKey)},
		OnWarning: func(w snapshot.Warning) {
			log.Printf("snapshot site warning: site_id=%q reason=%q", w.SiteID, w.Message)
			alertCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if alertErr := repository.WarnSite(alertCtx, w.SiteID, w.Message); alertErr != nil {
				log.Printf("snapshot site warning could not be persisted: site_id=%q error=%q", w.SiteID, alertErr.Error())
			}
		},
	}
	triggers := make(chan struct{}, 1)
	unsubscribe, err := nc.Subscribe("config.changed", func([]byte) {
		select {
		case triggers <- struct{}{}:
		default:
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe config.changed: %w", err)
	}
	defer func() { _ = unsubscribe() }()
	go func() {
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				dispatchCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
				n, dispatchErr := repository.DispatchOutbox(dispatchCtx, func(payload []byte) error {
					if publishErr := nc.Publish("config.changed", payload); publishErr != nil {
						return publishErr
					}
					return nc.Flush()
				})
				cancel()
				if dispatchErr != nil {
					log.Printf("config outbox dispatch failed: %q", dispatchErr.Error())
				}
				if n > 0 {
					log.Printf("config outbox events published: count=%d", n)
				}
			}
		}
	}()
	triggers <- struct{}{} // Initial build reconciles the region after worker restarts.
	go func() {
		err := snapshot.RunDebounced(ctx, triggers, 3*time.Second, func(buildCtx context.Context) error {
			record, buildErr := builder.Build(buildCtx, region)
			if buildErr != nil {
				return buildErr
			}
			if publishErr := snapshot.NotifyUpdated(nc, region, record); publishErr != nil {
				return fmt.Errorf("publish config.updated: %w", publishErr)
			}
			log.Printf("snapshot published: region=%q version=%d checksum=%q", region, record.Version, record.Checksum)
			return nil
		}, func(buildErr error) {
			log.Printf("snapshot build failed; previous active snapshot retained: %q", buildErr.Error())
		})
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("snapshot event loop stopped: %q", err.Error())
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /internal/snapshot", snapshot.EdgeHandler{Repository: repository, Objects: objects, Resolver: repository})
	server := &http.Server{Addr: env("WORKER_ADDR", ":8082"), Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	certFile, keyFile, caFile := os.Getenv("WORKER_TLS_CERT_FILE"), os.Getenv("WORKER_TLS_KEY_FILE"), os.Getenv("EDGE_CLIENT_CA_FILE")
	if certFile == "" || keyFile == "" || caFile == "" {
		return errors.New("WORKER_TLS_CERT_FILE, WORKER_TLS_KEY_FILE, and EDGE_CLIENT_CA_FILE are required for internal snapshot mTLS")
	}
	caPEM, err := readConfiguredFile(caFile)
	if err != nil {
		return fmt.Errorf("read edge client CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caPEM) {
		return errors.New("EDGE_CLIENT_CA_FILE contains no valid certificates")
	}
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: caPool}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("snapshot worker listening with mTLS on %s region=%q", server.Addr, region)
	err = server.ListenAndServeTLS(certFile, keyFile)
	if errors.Is(err, http.ErrServerClosed) {
		return ctx.Err()
	}
	return err
}

func readConfiguredFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("configured file path is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(filepath.Dir(absolute))
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	return root.ReadFile(filepath.Base(absolute))
}

func privateKey(encoded string) (ed25519.PrivateKey, error) {
	if strings.TrimSpace(encoded) == "" {
		return nil, errors.New("SNAPSHOT_SIGNING_PRIVATE_KEY is required")
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(encoded)
	}
	if err != nil {
		return nil, errors.New("SNAPSHOT_SIGNING_PRIVATE_KEY must be base64 encoded")
	}
	if len(raw) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(raw), nil
	}
	if len(raw) != ed25519.PrivateKeySize {
		return nil, errors.New("SNAPSHOT_SIGNING_PRIVATE_KEY has invalid length")
	}
	return ed25519.PrivateKey(raw), nil
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
