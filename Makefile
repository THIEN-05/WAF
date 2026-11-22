.PHONY: up up-wait down test test-integration lint build bench gen migrate dev-check

up:
	docker compose -f deploy/docker-compose.yml up -d

up-wait:
	docker compose -f deploy/docker-compose.yml up -d --wait

down:
	docker compose -f deploy/docker-compose.yml down

test:
	go test -race ./...

test-integration:
	go test -tags=integration -count=1 -v ./edge/internal/ratelimit

lint:
	golangci-lint run ./...

build:
	go build ./edge/cmd/edge ./controlplane/cmd/api ./controlplane/cmd/worker ./controlplane/cmd/ingest

bench:
	go test -run '^$$' -bench=. ./...

gen:
	@echo "No generators are configured yet."

migrate:
	@echo "No migrations are configured yet."

dev-check:
	@if command -v sh >/dev/null 2>&1; then ./scripts/dev-check.sh; else powershell -NoProfile -ExecutionPolicy Bypass -File scripts/dev-check.ps1; fi
