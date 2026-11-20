package main

import (
	"log"

	"github.com/example/wafplatform/pkg/server"
)

func main() {
	if err := server.Run("ingest", server.Env("INGEST_ADDR", ":8083")); err != nil {
		log.Fatalf("ingest server gặp lỗi: %v", err)
	}
}
