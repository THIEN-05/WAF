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
- **Đã xác minh bổ sung sau vòng sửa lint:** golangci-lint v2.1.6 `run ./...` → `0 issues`; `go vet ./...` → PASS; `go test -count=1 ./...` → PASS (Windows cần quyền loopback cho httptest). CI ghim golangci-lint `v2.1.6` và dùng `go test -race -count=1 ./...`.
- **Chưa xác minh cục bộ:** `go test -race -count=1 ./...`; lệnh thực tế báo `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`. Máy hiện `CGO_ENABLED=0`, không có GCC/Clang khả dụng; Docker và WSL cũng không truy cập được trong session này. Chưa có kết quả run từ GitHub Actions.
- Lệnh tự chạy lại: `gofmt -w edge controlplane pkg`; `go vet ./...`; `go build ./...`; `go test -count=1 ./...`; `go test -race -count=1 ./...`; `golangci-lint run ./...` (golangci-lint v2.1.6).
- Benchmark P2: chưa chạy, không có số liệu throughput được báo cáo.

### TODO P2

1. Hỗ trợ PROXY protocol v2 để tương thích NLB.
2. Thay JA3/JA4 stub bằng fingerprint ClientHello đã kiểm thử.
3. Tích hợp phân phối cert/secret qua mTLS với control plane và kiểm chứng luồng production.
4. Thay exporter metrics tự viết bằng `client_golang` khi dependency có thể được tải; giữ interface Metrics và không thêm nhãn `site_id`.
5. Cài môi trường có CGO/GCC và golangci-lint hoặc nhận kết quả CI thật để xác nhận race/lint xanh.

## Vòng sửa lint theo yêu cầu

- Đã sửa toàn bộ 35 diagnostics ban đầu của golangci-lint v2.1.6; không thay đổi/nới `.golangci.yml`.
- `pkg/wafcore/dsl.go:331`: phép gán `fieldNode` là thừa, vì dòng ngay sau thay `left` bằng `callNode` và không đọc giá trị cũ. Không phải bug parser; đã bỏ assignment.
- Đã thêm test round-robin với bộ đếm `^uint64(0)` để kiểm tra phép modulo trước khi ép sang `int`.
- Đã kiểm tra `Write`, `Sync`, `Close` của snapshot tạm trước rename; lỗi làm dừng rename và cleanup file tạm.
- Đã thêm `//nolint:gosec` có lý do cụ thể tại các đường dẫn config do operator cung cấp, sau khi chuẩn hóa bằng `filepath.Clean`.
- Lệnh lint chạy tại máy qua `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.1.6 run ./...` cho kết quả `0 issues.`

## P3 — access control và rate limiting

- Đã thêm `edge/internal/access`: binary radix tree dual-stack IPv4/IPv6; thứ tự allow → ban/block IP → country/ASN → global CIDR blocklist → hook Under Attack; `BanTable` giới hạn số IP và TTL; enforcement gói Free/Pro/Business/Enterprise.
- Đã thêm `GeoResolver`, fake resolver và `MMDBResolver` dùng `maxminddb.Reader` memory-map. Edge đọc đường dẫn từ `EDGE_GEOIP_COUNTRY_MMDB`, `EDGE_GEOIP_ASN_MMDB`; danh sách global CIDR khởi đầu đọc từ `EDGE_GLOBAL_BLOCKLIST_CIDRS`. Lookup Geo được cache trên RequestCtx.
- Đã thêm `edge/internal/ratelimit`: token bucket micro-token dùng atomic CAS, sliding window, shard map với cap toàn cục và `max_counter_keys` theo site, key hash cố định, TTL/dọn batch; key `ip`, `ip+path`, `header:`, `cookie:`, `ja3`, `site`; action/rule ID, `ban_s`, 429 và Retry-After.
- Redis dùng go-redis ghim `v9.7.3`, Lua `INCR`/`PEXPIRE` theo batch bất đồng bộ và cache ngưỡng phân tán eventual. Local limiter luôn quyết định không chờ Redis; khi Redis batch lỗi, cache Redis bị bỏ qua và local tiếp tục enforcement.
- Đã nối access rồi rate-limit vào pipeline edge mặc định. `block`/`throttle` trả 429; `challenge` dùng challenge response. Rate limit ghi `request_id` và `rule_id` vào log tiếng Việt.
- Đã thêm k6 script `test/k6/ratelimit.js` để xác nhận POST `/login` nhận 429 khi vượt hạn mức.
- **Đã xác minh:** golangci-lint v2.1.6 → `0 issues`; `go vet ./...` PASS; `go build ./...` PASS; `go test -count=1 ./...` PASS. Test mới gồm: IPv4/IPv6 radix, thứ tự access + Geo lazy/cache, entitlement theo gói, ban TTL/cap, fake Geo + lỗi mở MMDB, token bucket đồng hồ giả, concurrency 100 goroutine, sliding window, cap/cleanup TTL, tất cả key type, `ban_s`, `Retry-After` 429, batch Lua và Redis-down fallback local.
- **Chưa xác minh:** `go test -race -count=1 ./...` không chạy trên máy này: Go báo `-race requires cgo`, `CGO_ENABLED=0`, không có GCC/Clang khả dụng. CI đã chạy lệnh race trên Ubuntu nhưng chưa có run result mới.
- **Chưa chạy ngoài máy:** k6 chưa cài; Redis thật qua Compose không kiểm chứng được vì Docker API trả `permission denied`; không có file MaxMind MMDB thật để test lookup (fake resolver được test, và test xác nhận file MMDB hỏng bị từ chối).
- Lệnh tự chạy lại: `golangci-lint run ./...`; `go vet ./...`; `go build ./...`; `go test -count=1 ./...`; `go test -race -count=1 ./...`; sau khi chạy edge với snapshot/policy `POST /login`, `k6 run -e BASE_URL=http://127.0.0.1:8080 -e SITE_HOST=site.test test/k6/ratelimit.js`.
- Benchmark P3: chưa chạy; không có số liệu hiệu năng được báo cáo.

### TODO P3

1. Chạy CI race trên runner Ubuntu để xác nhận data race bằng `go test -race -count=1 ./...`.
2. Chạy k6 và test Lua với Redis service thật trong môi trường Docker có quyền truy cập daemon.
3. Kiểm thử GeoIP/ASN lookup với bộ MMDB hợp lệ được cấp phép; không commit dữ liệu MMDB vào repo.
4. Chuyển global blocklist từ biến môi trường sang danh sách có chữ ký đi cùng snapshot/ConfigSync; nối hook Under Attack với state/override từ CP.

### TODO

1. Bổ sung logic nghiệp vụ và test tích hợp khi bắt đầu phase tiếp theo.
2. Chọn DNS provider và hoàn thiện policy pháp lý trước khi mở dịch vụ cho khách thật.
