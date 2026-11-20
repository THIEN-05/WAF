package main

import "github.com/example/wafplatform/pkg/server"

func main() { server.Run("worker", server.Env("WORKER_ADDR", ":8082")) }
