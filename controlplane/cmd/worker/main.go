package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/example/wafplatform/controlplane/internal/fleet"
	"github.com/example/wafplatform/controlplane/internal/platform/db"
	platformnats "github.com/example/wafplatform/controlplane/internal/platform/nats"
	"github.com/example/wafplatform/controlplane/internal/platform/secret"
	"github.com/example/wafplatform/controlplane/internal/snapshot"
	"github.com/google/uuid"
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

	certFile, keyFile, clientCAPath := os.Getenv("WORKER_TLS_CERT_FILE"), os.Getenv("WORKER_TLS_KEY_FILE"), os.Getenv("EDGE_CLIENT_CA_FILE")
	if certFile == "" || keyFile == "" {
		return errors.New("WORKER_TLS_CERT_FILE and WORKER_TLS_KEY_FILE are required for internal TLS")
	}
	var clientCAPEM []byte
	if clientCAPath != "" {
		clientCAPEM, err = readConfiguredFile(clientCAPath)
		if err != nil {
			return fmt.Errorf("read edge client CA: %w", err)
		}
	}
	caCertificatePath := os.Getenv("EDGE_CA_CERT_FILE")
	if caCertificatePath == "" && len(clientCAPEM) > 0 {
		caCertificatePath = clientCAPath
	}
	var caCertificatePEM []byte
	if caCertificatePath != "" {
		caCertificatePEM, err = readConfiguredFile(caCertificatePath)
		if err != nil {
			return fmt.Errorf("read edge signing CA certificate: %w", err)
		}
	}
	caStore := secret.NewMemory()
	caAuthority, caPEM, err := loadEdgeAuthority(ctx, caCertificatePEM, os.Getenv("EDGE_CA_KEY_FILE"), os.Getenv("APP_ENV"), caStore)
	if err != nil {
		return err
	}
	if len(clientCAPEM) == 0 {
		clientCAPEM = caPEM
	}
	if !bytesEqualCertificates(caPEM, clientCAPEM) {
		return errors.New("EDGE_CA_CERT_FILE and EDGE_CLIENT_CA_FILE must identify the same internal CA")
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(clientCAPEM) {
		return errors.New("EDGE_CLIENT_CA_FILE contains no valid certificates")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.Handle("GET /internal/snapshot", snapshot.EdgeHandler{Repository: repository, Objects: objects, Resolver: repository})
	fleetService := fleet.Service{Pool: pool.Pool, CA: caAuthority}
	mux.HandleFunc("POST /internal/edges/register", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "secure transport required", http.StatusUpgradeRequired)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var request struct {
			Token string `json:"token"`
			CSR   string `json:"csr"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid registration request", http.StatusBadRequest)
			return
		}
		registration, registerErr := fleetService.Register(r.Context(), request.Token, []byte(request.CSR), caPEM)
		if registerErr != nil {
			if errors.Is(registerErr, fleet.ErrBootstrapRejected) {
				http.Error(w, "bootstrap token rejected", http.StatusUnauthorized)
			} else {
				http.Error(w, "registration rejected", http.StatusBadRequest)
			}
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(registration)
	})
	mux.HandleFunc("POST /internal/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
			return
		}
		edgeID, ok := edgeIDFromCertificate(r.TLS.PeerCertificates[0])
		if !ok {
			http.Error(w, "edge identity is invalid", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var heartbeat fleet.Heartbeat
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&heartbeat); err != nil {
			http.Error(w, "invalid heartbeat", http.StatusBadRequest)
			return
		}
		if err := fleetService.Heartbeat(r.Context(), edgeID, r.TLS.PeerCertificates[0].SerialNumber.Text(16), heartbeat); err != nil {
			if errors.Is(err, fleet.ErrEdgeCertificateRejected) {
				http.Error(w, "edge certificate rejected", http.StatusUnauthorized)
			} else {
				http.Error(w, "heartbeat rejected", http.StatusConflict)
			}
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("POST /internal/edges/renew", func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "mTLS client certificate required", http.StatusUnauthorized)
			return
		}
		peer := r.TLS.PeerCertificates[0]
		edgeID, ok := edgeIDFromCertificate(peer)
		if !ok {
			http.Error(w, "edge identity is invalid", http.StatusUnauthorized)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
		var request struct {
			CSR string `json:"csr"`
		}
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&request); err != nil {
			http.Error(w, "invalid renewal request", http.StatusBadRequest)
			return
		}
		registration, err := fleetService.RenewCertificate(r.Context(), edgeID, peer.SerialNumber.Text(16), []byte(request.CSR), caPEM)
		if err != nil {
			http.Error(w, "certificate renewal rejected", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		if err = json.NewEncoder(w).Encode(registration); err != nil {
			log.Printf("edge certificate renewal response failed")
		}
	})
	workerAddr := env("WORKER_ADDR", "127.0.0.1:8082")
	if err := validateWorkerBind(workerAddr, os.Getenv("WORKER_ALLOW_NETWORK") == "true"); err != nil {
		return err
	}
	server := &http.Server{Addr: workerAddr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
	// A new edge cannot present a client certificate during bootstrap. Registration
	// therefore uses HTTPS plus its one-time token; all post-enrollment routes enforce
	// verified client certificates in their handlers.
	server.TLSConfig = &tls.Config{MinVersion: tls.VersionTLS12, ClientAuth: tls.VerifyClientCertIfGiven, ClientCAs: caPool}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	go func() {
		ticker := time.NewTicker(20 * time.Second)
		defer ticker.Stop()
		providers := map[string]fleet.DNSProvider{"cloudflare": fleet.ProviderStub{Name: "cloudflare"}, "route53": fleet.ProviderStub{Name: "route53"}}
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				_ = now
				sweepCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
				if err := fleetService.SweepHealth(sweepCtx, providers, 90*time.Second, 3, 1); err != nil {
					log.Printf("edge health sweep failed: %q", err.Error())
				}
				cancel()
			}
		}
	}()
	log.Printf("snapshot worker listening with mTLS on %s region=%q", server.Addr, region)
	err = server.ListenAndServeTLS(certFile, keyFile)
	if errors.Is(err, http.ErrServerClosed) {
		return ctx.Err()
	}
	return err
}

func validateWorkerBind(addr string, allowNetwork bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("invalid WORKER_ADDR: %w", err)
	}
	if host == "localhost" {
		return nil
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsLoopback() {
		return nil
	}
	if !allowNetwork {
		return errors.New("non-loopback WORKER_ADDR requires WORKER_ALLOW_NETWORK=true; TLS is mandatory")
	}
	return nil
}

func edgeIDFromCertificate(cert *x509.Certificate) (uuid.UUID, bool) {
	if cert == nil {
		return uuid.Nil, false
	}
	for _, identity := range cert.URIs {
		if identity == nil || identity.Scheme != "spiffe" || identity.Host != "waf" {
			continue
		}
		parsed, err := url.Parse(identity.String())
		if err != nil {
			continue
		}
		const prefix = "/edge/"
		if len(parsed.Path) <= len(prefix) || parsed.Path[:len(prefix)] != prefix {
			continue
		}
		id, err := uuid.Parse(parsed.Path[len(prefix):])
		if err == nil && cert.Subject.CommonName == id.String() {
			return id, true
		}
	}
	return uuid.Nil, false
}

func loadEdgeAuthority(ctx context.Context, certificatePEM []byte, keyFile, appEnv string, store secret.Store) (*fleet.Authority, []byte, error) {
	if store == nil {
		return nil, nil, errors.New("edge CA SecretStore is required")
	}
	var privatePEM []byte
	var err error
	if keyFile == "" {
		if strings.EqualFold(appEnv, "production") || len(certificatePEM) != 0 {
			return nil, nil, errors.New("configured edge CA certificate requires EDGE_CA_KEY_FILE")
		}
		certificatePEM, privatePEM, err = fleet.NewDevelopmentAuthorityPEM(time.Now())
	} else {
		if len(certificatePEM) == 0 {
			return nil, nil, errors.New("EDGE_CA_CERT_FILE is required with EDGE_CA_KEY_FILE")
		}
		privatePEM, err = readPrivateCAKeyFile(keyFile)
	}
	if err != nil {
		return nil, nil, err
	}
	defer clear(privatePEM)
	const secretName = "edge-ca/private-key"
	if err = store.Put(ctx, secretName, privatePEM); err != nil {
		return nil, nil, errors.New("store edge CA private key")
	}
	storedPEM, err := store.Get(ctx, secretName)
	if err != nil {
		return nil, nil, errors.New("load edge CA private key from SecretStore")
	}
	defer clear(storedPEM)
	authority, err := fleet.NewAuthorityFromPEM(certificatePEM, storedPEM)
	if err != nil {
		return nil, nil, fmt.Errorf("load edge CA from SecretStore: %w", err)
	}
	return authority, append([]byte(nil), certificatePEM...), nil
}

func readPrivateCAKeyFile(path string) ([]byte, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, errors.New("resolve edge CA key path")
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return nil, errors.New("resolve edge CA key file")
	}
	if root := repositoryRoot(); root != "" {
		root, err = filepath.EvalSymlinks(root)
		if err == nil {
			relative, relErr := filepath.Rel(root, resolved)
			if relErr == nil && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)))) {
				return nil, errors.New("edge CA private key file must be outside the repository")
			}
		}
	}
	rootDir, err := os.OpenRoot(filepath.Dir(resolved))
	if err != nil {
		return nil, errors.New("open edge CA key directory")
	}
	defer func() { _ = rootDir.Close() }()
	base := filepath.Base(resolved)
	info, err := rootDir.Stat(base)
	if err != nil {
		return nil, errors.New("read edge CA key file metadata")
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("edge CA key path must be a regular file")
	}
	permissions := info.Mode().Perm()
	if runtime.GOOS != "windows" && permissions != 0o400 && permissions != 0o600 {
		return nil, errors.New("edge CA private key file must have mode 0600 or stricter")
	}
	return rootDir.ReadFile(base)
}

func repositoryRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	for directory := cwd; ; directory = filepath.Dir(directory) {
		if _, err := os.Stat(filepath.Join(directory, ".git")); err == nil {
			return directory
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			return ""
		}
	}
}

func bytesEqualCertificates(a, b []byte) bool {
	blockA, _ := pem.Decode(a)
	blockB, _ := pem.Decode(b)
	if blockA == nil || blockB == nil || blockA.Type != "CERTIFICATE" || blockB.Type != "CERTIFICATE" {
		return false
	}
	certA, errA := x509.ParseCertificate(blockA.Bytes)
	certB, errB := x509.ParseCertificate(blockB.Bytes)
	return errA == nil && errB == nil && bytes.Equal(certA.Raw, certB.Raw)
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
