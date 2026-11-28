package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/example/wafplatform/controlplane/internal/analytics"
	"github.com/example/wafplatform/controlplane/internal/platform/db"
	platformredis "github.com/example/wafplatform/controlplane/internal/platform/redis"
	"github.com/nats-io/nats.go"
)

const maxHTTPBatch = 4 << 20

func main() {
	if err := run(); err != nil && !errors.Is(err, context.Canceled) {
		log.Printf("ingest stopped: %v", err)
		os.Exit(1)
	}
}

func run() error {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		return errors.New("DATABASE_URL is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	startup, stopStartup := context.WithTimeout(ctx, 10*time.Second)
	defer stopStartup()
	pool, err := db.OpenWorker(startup, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	redisClient, err := platformredis.Open(startup, env("REDIS_ADDR", "127.0.0.1:6379"), os.Getenv("REDIS_PASSWORD"), 0)
	if err != nil {
		return fmt.Errorf("connect Redis: %w", err)
	}
	defer redisClient.Close()
	writer := analytics.ClickHouseHTTP{Endpoint: env("CLICKHOUSE_URL", "http://127.0.0.1:8123"), Database: env("CLICKHOUSE_DATABASE", "waf"), Username: os.Getenv("CLICKHOUSE_USER"), Password: os.Getenv("CLICKHOUSE_PASSWORD")}
	batcher := &analytics.Batcher{Processor: analytics.Processor{Resolver: analytics.RedisSiteResolver{Cache: redisClient, Pool: pool.Pool, TTL: 30 * time.Second}}, Writer: writer, DeadLetters: &analytics.FileDeadLetter{Path: env("INGEST_DLQ_PATH", "var/ingest-dead-letter.jsonl")}, QueueSize: 4096, MaxRows: 10_000, FlushInterval: time.Second}
	batcherDone, err := batcher.Start(ctx)
	if err != nil {
		return err
	}
	natsConn, err := connectNATS(env("NATS_URL", "nats://127.0.0.1:4222"))
	if err != nil {
		return fmt.Errorf("connect NATS: %w", err)
	}
	defer natsConn.Close()
	var queueRejected atomic.Uint64
	var deadLetterFailures atomic.Uint64
	sub, err := natsConn.Subscribe("edge.logs.v1", func(msg *nats.Msg) {
		if enqueueErr := batcher.Enqueue(msg.Data); enqueueErr != nil {
			count := queueRejected.Add(1)
			if count == 1 || count%1000 == 0 {
				log.Printf("ingest queue rejected messages=%d", count)
			}
			if dlErr := batcher.DeadLetters.Put(context.Background(), msg.Data, enqueueErr); dlErr != nil {
				failures := deadLetterFailures.Add(1)
				if failures == 1 || failures%1000 == 0 {
					log.Printf("ingest dead-letter write failures=%d", failures)
				}
			}
		}
	})
	if err != nil {
		return fmt.Errorf("subscribe NATS ingest subject: %w", err)
	}
	defer sub.Unsubscribe()
	if err = natsConn.FlushTimeout(3 * time.Second); err != nil {
		return fmt.Errorf("flush NATS subscription: %w", err)
	}

	serverTLS, err := ingestServerTLS()
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("POST /v1/ingest", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "verified client certificate required", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxHTTPBatch)
		payload, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			http.Error(w, "invalid ingest batch", http.StatusRequestEntityTooLarge)
			return
		}
		if enqueueErr := batcher.Enqueue(payload); enqueueErr != nil {
			if errors.Is(enqueueErr, analytics.ErrIngestQueueFull) {
				w.Header().Set("Retry-After", "1")
				http.Error(w, "ingest queue full", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, "invalid ingest batch", http.StatusBadRequest)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
	server := &http.Server{Addr: env("INGEST_ADDR", ":8083"), Handler: mux, TLSConfig: serverTLS, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.ListenAndServeTLS(os.Getenv("INGEST_TLS_CERT_FILE"), os.Getenv("INGEST_TLS_KEY_FILE"))
	}()
	log.Printf("ingest online addr=%q subject=%q batch_rows=10000 flush=1s", server.Addr, "edge.logs.v1")
	select {
	case <-ctx.Done():
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		_ = server.Shutdown(shutdownCtx)
		select {
		case batchErr := <-batcherDone:
			if batchErr != nil {
				return batchErr
			}
		case <-time.After(10 * time.Second):
			return errors.New("ingest batcher shutdown timed out")
		}
		return nil
	case batchErr := <-batcherDone:
		_ = server.Shutdown(context.Background())
		if batchErr == nil {
			return errors.New("ingest batcher stopped unexpectedly")
		}
		return batchErr
	case err = <-serveErr:
		cancel()
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func ingestServerTLS() (*tls.Config, error) {
	certPath, keyPath, caPath := os.Getenv("INGEST_TLS_CERT_FILE"), os.Getenv("INGEST_TLS_KEY_FILE"), os.Getenv("INGEST_CLIENT_CA_FILE")
	if certPath == "" || keyPath == "" || caPath == "" {
		return nil, errors.New("INGEST_TLS_CERT_FILE, INGEST_TLS_KEY_FILE and INGEST_CLIENT_CA_FILE are required for mTLS ingest")
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return nil, fmt.Errorf("load ingest TLS identity: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return nil, fmt.Errorf("read ingest client CA: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("INGEST_CLIENT_CA_FILE contains no certificates")
	}
	return &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool}, nil
}

func connectNATS(address string) (*nats.Conn, error) {
	certPath, keyPath, caPath := os.Getenv("INGEST_NATS_CLIENT_CERT"), os.Getenv("INGEST_NATS_CLIENT_KEY"), os.Getenv("INGEST_NATS_CA_FILE")
	secure := certPath != "" || keyPath != "" || caPath != ""
	if secure && (certPath == "" || keyPath == "" || caPath == "") {
		return nil, errors.New("NATS TLS client certificate, key, and CA must be configured together")
	}
	if env("APP_ENV", "development") == "production" && !secure {
		return nil, errors.New("production ingest requires mutual TLS to NATS")
	}
	options := []nats.Option{nats.Name("waf-ingest"), nats.Timeout(3 * time.Second)}
	if secure {
		pair, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return nil, fmt.Errorf("load NATS client identity: %w", err)
		}
		caPEM, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read NATS CA: %w", err)
		}
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(caPEM) {
			return nil, errors.New("INGEST_NATS_CA_FILE contains no certificates")
		}
		options = append(options, nats.Secure(&tls.Config{MinVersion: tls.VersionTLS12, Certificates: []tls.Certificate{pair}, RootCAs: roots}))
	}
	return nats.Connect(address, options...)
}

func env(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}
