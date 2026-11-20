package main

import "github.com/example/wafplatform/pkg/server"

func main() { server.Run("api", server.Env("API_ADDR", ":8081")) }
