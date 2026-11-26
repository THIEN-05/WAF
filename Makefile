.PHONY: up up-wait down test test-integration test-cp-integration lint build bench gen migrate dev-check check-cp-sql check-generated

up:
	docker compose -f deploy/docker-compose.yml up -d

up-wait:
	docker compose -f deploy/docker-compose.yml up -d --wait

down:
	docker compose -f deploy/docker-compose.yml down

test:
	go test -race ./...

test-integration:
	go test -tags=integration -race -count=1 -v ./edge/internal/ratelimit ./edge/internal/telemetry

test-cp-integration:
	go test -tags=integration -race -count=20 -v ./controlplane/internal/integration

check-cp-sql:
	bash scripts/check-controlplane-sql.sh

check-generated:
	@if [ -n "$$(gofmt -l $$(git ls-files --cached --others --exclude-standard -- '*.go'))" ]; then gofmt -l $$(git ls-files --cached --others --exclude-standard -- '*.go'); exit 1; fi
	go mod tidy
	$(MAKE) gen
	git diff --exit-code

lint:
	golangci-lint run ./...

build:
	go build ./edge/cmd/edge ./controlplane/cmd/api ./controlplane/cmd/worker ./controlplane/cmd/ingest

bench:
	go test -run '^$$' -bench=. ./...

gen:
	go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.9.0 -config controlplane/openapi/oapi-codegen.yaml controlplane/openapi/v1.yaml
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0 generate -f sqlc.yaml

migrate:
	go run ./controlplane/cmd/migrate up

dev-check:
	@if command -v sh >/dev/null 2>&1; then ./scripts/dev-check.sh; else powershell -NoProfile -ExecutionPolicy Bypass -File scripts/dev-check.ps1; fi
