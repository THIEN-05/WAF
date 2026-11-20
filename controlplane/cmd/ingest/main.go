package main

import "github.com/example/wafplatform/pkg/server"

func main() { server.Run("ingest", server.Env("INGEST_ADDR", ":8083")) }
