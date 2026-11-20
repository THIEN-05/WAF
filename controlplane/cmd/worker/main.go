package main

import (
	"log"

	"github.com/example/wafplatform/pkg/server"
)

func main() {
	if err := server.Run("worker", server.Env("WORKER_ADDR", ":8082")); err != nil {
		log.Fatalf("worker server gặp lỗi: %v", err)
	}
}
