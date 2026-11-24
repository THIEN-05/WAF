package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/wafplatform/controlplane/internal/api"
	"github.com/example/wafplatform/controlplane/internal/platform/config"
	"github.com/example/wafplatform/controlplane/internal/platform/db"
	"github.com/example/wafplatform/controlplane/internal/platform/logger"
	platformnats "github.com/example/wafplatform/controlplane/internal/platform/nats"
	platformredis "github.com/example/wafplatform/controlplane/internal/platform/redis"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pool, err := db.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	rc, err := platformredis.Open(ctx, cfg.RedisAddr, cfg.RedisPassword, cfg.RedisDB)
	if err != nil {
		return errors.New("connect Redis")
	}
	defer func() { _ = rc.Close() }()
	nc, err := platformnats.Connect(cfg.NATSURL)
	if err != nil {
		return errors.New("connect NATS")
	}
	defer nc.Close()
	s, err := api.New(cfg, pool, rc, logger.New())
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.APIAddr, Handler: s.Router(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 20}
	stopCtx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() {
		<-stopCtx.Done()
		shutdown, c := context.WithTimeout(context.Background(), 10*time.Second)
		defer c()
		_ = srv.Shutdown(shutdown)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
