package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/example/wafplatform/controlplane/internal/fleet"
	"github.com/example/wafplatform/controlplane/internal/platform/db"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) != 4 || os.Args[1] != "create-bootstrap" {
		return errors.New("usage: fleetctl create-bootstrap <region> <provider>")
	}
	databaseURL := os.Getenv("WORKER_DATABASE_URL")
	if databaseURL == "" {
		return errors.New("WORKER_DATABASE_URL is required")
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	openCtx, closeOpen := context.WithTimeout(ctx, 10*time.Second)
	defer closeOpen()
	pool, err := db.OpenWorker(openCtx, databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	bootstrap, err := (fleet.Service{Pool: pool.Pool}).CreateBootstrapToken(ctx, strings.TrimSpace(os.Args[2]), strings.TrimSpace(os.Args[3]))
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(bootstrap)
}
