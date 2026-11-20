# Tiến độ

## P0 — Scaffold repository

- Đã tạo cấu trúc thư mục theo AGENTS.md, module Go, Makefile, cấu hình lint/editor/git và `.env.example`.
- Đã thêm Compose cho PostgreSQL, Redis, NATS JetStream, ClickHouse, MinIO và Mailhog, mỗi dịch vụ có healthcheck.
- Đã thêm GitHub Actions lint → test → govulncheck.
- Đã thêm bốn binary skeleton với cấu hình env, `/healthz` và graceful shutdown.
- Đã ghi các quyết định MVP và mặc định cho mục 13 trong `docs/DECISIONS.md`.
- Đã thêm `.devcontainer/` với Go, Docker-in-Docker, make, gcc và golangci-lint; cùng script `scripts/dev-check.sh` để liệt kê công cụ còn thiếu.
- CI chạy tuần tự golangci-lint → `go test -race ./...` → govulncheck; job Compose riêng khởi động dịch vụ bằng `docker compose ... up -d --wait` rồi dọn bằng `down -v`.
- **Đã xác minh cục bộ:** `go test ./...`; build 4 binary; `docker compose -f deploy/docker-compose.yml config -q`.
- **Chưa xác minh cục bộ:** `make up` (Docker daemon chưa chạy); `go test -race ./...` (host thiếu CGO compiler); golangci-lint (chưa cài trên host).
- Lệnh tự chạy lại trong Dev Container/Linux có Docker:
  - `make up-wait` — khởi động dịch vụ và đợi healthcheck.
  - `make test` — chạy `go test -race ./...`.
  - `make lint` — chạy golangci-lint.
  - `docker compose -f deploy/docker-compose.yml down -v` — dọn dịch vụ và volume dev.
  - `./scripts/dev-check.sh` — báo công cụ có/thiếu trên host.
- Benchmark: chưa chạy; không có số liệu hiệu năng được báo cáo.

## P1 — `pkg/wafcore`

- Hoàn tất snapshot schema v1 với JSON/YAML tags, validation có đường dẫn lỗi, entitlements và tham chiếu secret (không chứa secret rõ).
- Hoàn tất log event schema v1 theo data-plane 5.13 và `site_stats_1m` theo control-plane analytics schema.
- Hoàn tất envelope gzip JSON, SHA-256 checksum và Ed25519 ký/verify theo `kid`, hỗ trợ key rotation qua map nhiều public key; payload giải nén bị giới hạn 32 MiB.
- Hoàn tất DSL lexer, Pratt parser, AST/type checking, optimizer, RE2 precompile, CIDR, getters qua `Ctx`, short-circuit closure và actions typed.
- Đã xác minh: `go test ./...`, build bốn binary, `go test -cover ./pkg/wafcore` (82.5%), fuzz 60 giây PASS (3,542,196 executions, không panic), benchmark `BenchmarkRulesPerSecond` chạy 1 giây.
- Đã thêm fixture dùng chung `test/fixtures/snapshot.sample.yaml`, YAML → struct → JSON → struct round-trip và so sánh `reflect.DeepEqual`.
- Đã thêm 13 golden case kiểm tra nguyên văn lỗi DSL, bao gồm dòng/cột cho lỗi cú pháp và kiểu.
- CI được cấu hình lint `./...` rồi `go test -race ./...`; **chưa xác nhận run xanh** vì checkout này không có kết nối đọc/chạy GitHub Actions. Host Windows cũng thiếu CGO compiler, golangci-lint và Docker daemon.
- Benchmark trên Windows amd64, Intel Core i5-11400H: 1 rule 8.39M eval/s; 10 rules 8.39M rule-eval/s; 100 rules 8.53M rule-eval/s; 1,000 rules 8.48M rule-eval/s. Đây là microbenchmark closure đơn, không phải benchmark request/edge.
- Lệnh chạy lại trong Dev Container/CI: `make lint && make test` (lint toàn repo, race test toàn repo); YAML test: `go test ./pkg/wafcore -run TestSnapshotYAMLRoundTrip`; golden tests: `go test ./pkg/wafcore -run TestDSLErrorGolden`.
- YAML parser dùng dependency `gopkg.in/yaml.v3 v3.0.1`, đã ghim trong `go.mod`/`go.sum`.
- Còn lại: lấy kết quả xanh thật của GitHub Actions `lint` và `test` sau khi push; local host không thể thay thế xác nhận CI này.

## P2 — edge core

- Đã triển khai listener HTTP redirect + HTTP-01 callback, TLS 1.2+/ALPN, cert cache/default cert, giới hạn kết nối/IP, timeout/header cap và PROXY v1 theo CIDR tin cậy.
- Đã triển khai router host exact/wildcard, kiểm tra SNI/Host, trạng thái site và entitlement; RequestCtx lazy/pool; pipeline phase với Metrics interface và short-circuit.
- Đã triển khai proxy có lựa chọn weighted origin, health check/circuit breaker, retry GET/HEAD khi lỗi dial, WebSocket/SSE, header forwarding, Via loop detection, SSRF check lúc validate và dial; configsync atomic holder, signed load, LKG và unsigned local dev có chặn production.
- Đã triển khai `/healthz`, `/readyz`, cổng metrics riêng, graceful shutdown và panic recovery theo fail_mode. Log do edge phát ra đã chuyển sang tiếng Việt.
- **Đã xác minh cục bộ:** `gofmt`; `go vet ./...`; `go build ./...`; `go test ./...` (PASS khi được phép loopback cho httptest). Bản `go test ./...` trong sandbox thường bị Windows chặn loopback và thất bại; chạy lại với quyền loopback đã PASS toàn bộ packages.
- Các test P2 trong lần chạy xanh gồm: `TestProxyHTTP1HTTP2SSEAndWebSocket` (HTTP/1.1, HTTP/2, SSE, WebSocket echo), `TestSSEFlushesBeforeOriginCompletes`, `TestReloadDoesNotInterruptInFlightRequest`, `TestPanicRespectsFailMode`, `TestPanicAfterHeadersClosesConnectionAndCountsMetric`, `TestValidateOriginsBlocksLocalAddresses`, `TestValidateOriginsResolvesDNSAndRejectsPrivateTargets`, `TestDialRebindingBlocked`, `TestCircuitBreakerFiveFailuresAndHalfOpen`, `TestRetryOnlyGETAndHEADDialFailures`, `TestHostAndSiteStatusResponses`, `TestUnknownSNIUsesFallbackThenHTTPRejectsMismatch`, `TestPerIPConnectionLimit`, `TestReadHeaderTimeoutClosesSlowloris`, `TestProxyProtocolV1OnlyFromTrustedCIDR` và `TestSampleSnapshotServesThroughFakeOrigin`.
- **Chưa xác minh cục bộ:** `go test -race ./...` (host báo `-race requires cgo`; cần cài GCC/MinGW và bật CGO); `golangci-lint run ./...` (golangci-lint chưa cài). CI đã khai báo lint rồi race test, nhưng chưa có kết quả run từ GitHub Actions.
- Lệnh tự chạy lại: `gofmt -w edge`; `go vet ./...`; `go build ./...`; `go test ./...`; `go test -race ./...`; `golangci-lint run ./...`.
- Benchmark P2: chưa chạy, không có số liệu throughput được báo cáo.

### TODO P2

1. Hỗ trợ PROXY protocol v2 để tương thích NLB.
2. Thay JA3/JA4 stub bằng fingerprint ClientHello đã kiểm thử.
3. Tích hợp phân phối cert/secret qua mTLS với control plane và kiểm chứng luồng production.
4. Thay exporter metrics tự viết bằng `client_golang` khi dependency có thể được tải; giữ interface Metrics và không thêm nhãn `site_id`.
5. Cài môi trường có CGO/GCC và golangci-lint hoặc nhận kết quả CI thật để xác nhận race/lint xanh.

### TODO

1. Bổ sung logic nghiệp vụ và test tích hợp khi bắt đầu phase tiếp theo.
2. Chọn DNS provider và hoàn thiện policy pháp lý trước khi mở dịch vụ cho khách thật.
