package main

import (
	"log"

	"github.com/example/wafplatform/pkg/server"
)

func main() {
	if err := server.Run("api", server.Env("API_ADDR", ":8081")); err != nil {
		log.Fatalf("api server gặp lỗi: %v", err)
	}
}
