package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
)

func main() {
	if err := run(); err != nil {
		log.Print(err)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return fmt.Errorf("usage: migrate up|down|status")
	}
	url := os.Getenv("DATABASE_URL")
	if url == "" {
		return fmt.Errorf("DATABASE_URL is required")
	}
	db, err := sql.Open("pgx", url)
	if err != nil {
		return fmt.Errorf("open migration database: %w", err)
	}
	defer func() { _ = db.Close() }()
	if err = goose.SetDialect("postgres"); err != nil {
		return err
	}
	ctx := context.Background()
	switch os.Args[1] {
	case "up":
		err = goose.UpContext(ctx, db, "controlplane/migrations")
	case "down":
		err = goose.DownContext(ctx, db, "controlplane/migrations")
	case "status":
		err = goose.StatusContext(ctx, db, "controlplane/migrations")
	default:
		err = fmt.Errorf("unknown migration action %q", os.Args[1])
	}
	return err
}
