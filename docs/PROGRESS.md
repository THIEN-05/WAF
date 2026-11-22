# Tiến độ

## Kiểm chứng gần nhất — 2026-11-22

### Đã xác minh

- `golangci-lint run ./...` → PASS, `0 issues.`
- `go vet ./...` → PASS, exit 0.
- `go test -count=1 ./...` → PASS toàn bộ packages, exit 0 khi cho phép test loopback chạy ngoài sandbox Windows.
- `go test -count=1 ./pkg/wafcore ./edge/internal/access ./edge/internal/ratelimit ./edge/internal/router ./edge/internal/pipeline ./edge/internal/configsync` → PASS.
- `go test -tags=integration -count=1 -v ./edge/internal/ratelimit` → PASS, gồm cả hai test Redis thật; Redis tại `localhost:6379` truy cập được trong lần chạy này.
- Benchmark access/rate limit đã chạy 5 lần. Median và allocs/op được ghi trong `docs/BENCHMARKS.md`.
- `TestSnapshotYAMLRoundTrip` đọc `test/fixtures/snapshot.sample.yaml`, validate, round-trip YAML → JSON → struct và so sánh struct; `TestDSLErrorGolden` có 13 golden case với lỗi chính xác gồm dòng/cột.
- Test cần loopback đã được đặt tên `TestLoopback...` tại edgecore, listener và proxy. Chúng chỉ chạy được ngoài sandbox Windows có chặn loopback; lần chạy full test xanh ở trên được thực hiện với quyền loopback.

### Chưa xác minh — lệnh tự chạy lại

- **Loopback trong sandbox:** test cần loopback bị Windows sandbox chặn. Đặt tên test `TestLoopback...`; chạy `go test -count=1 ./...` ngoài sandbox Windows để xác minh chúng.

Các mục lịch sử bên dưới ghi phạm vi phase; trạng thái xác minh hiện tại trong mục này là nguồn mới nhất.

## Điều tra CI đỏ và cấu hình mới — 2026-11-22

### Workflow tại từng commit đỏ

- `d3b293c` (#1): workflow ghim `golangci-lint-action@v6` cùng golangci-lint `v2.0.2`. Đây là cặp action/linter không tương thích (action v6 không hỗ trợ dòng v2). Không có log của run này trong dữ liệu hiện có, nên không khẳng định nguyên văn thông báo lỗi. Job `test` phụ thuộc lint; `govulncheck` phụ thuộc test. Compose là job độc lập, không có `needs`.
- `94fba84` (#2): workflow ghim action v6 cùng linter `v2.1.6`, trùng cặp phiên bản trong log lỗi người dùng cung cấp. Không có run ID đi kèm log để gán chắc chắn thông báo đó riêng cho #2 hay #3. Nếu lint đỏ, job test và govulncheck bị chặn bởi `needs`; Compose vẫn là job độc lập.
- `3d4fba5` (#3): vẫn ghim action v6 và linter `v2.1.6`, nên cấu hình có cùng nguyên nhân tương thích. Workflow có thêm các bước Compose `config`, `pull`, `up --wait`, nhưng job Compose không phụ thuộc lint và có thể chạy độc lập. Chưa có log để nói nó pass hay fail.

Lấy log còn thiếu cho từng run: `gh run list --commit <commit>`, sau đó `gh run view <run-id> --log-failed`. Không suy đoán lỗi của test-race, govulncheck hoặc Compose khi chưa có log.

### Thay đổi workflow hiện tại

- Lint dùng `golangci-lint-action@v8` với linter `v2.1.6`.
- Lint, race test, govulncheck, Compose và integration là các job độc lập. Race test vẫn chạy `go test -race -count=1 ./...`; không bỏ lint, race hay test.
- Govulncheck cài CLI `golang.org/x/vuln/cmd/govulncheck@v1.1.4` theo phiên bản cố định; không dùng action mặc định cài `@latest`.
- Integration có job Redis riêng (Redis 7.4.2) và chạy `go test -tags=integration -count=1 -v ./edge/internal/ratelimit`.
- `go.mod` và `actions/setup-go` cùng ghim Go 1.22.8, khớp môi trường WSL người dùng. Quyết định được ghi tại `docs/DECISIONS.md`.

### Kiểm tra thay đổi hiện tại

- `golangci-lint run ./...` → PASS, `0 issues.` Local linter: v2.1.6.
- `go vet ./...` → PASS, exit 0.
- `go test -count=1 ./...` → PASS toàn bộ packages khi chạy ngoài sandbox loopback.
- `go test -tags=integration -count=1 -v ./edge/internal/ratelimit` → PASS, gồm test Lua đồng thời và test outage/recovery với Redis thật.
- `go test -race -count=1 ./...` trên Windows chưa chạy được: `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`; máy hiện có `CGO_ENABLED=0`, không tìm thấy gcc/clang. Workflow Ubuntu đã giữ nguyên race test làm job độc lập, nhưng thay đổi workflow chưa có kết quả GitHub Actions vì chưa được chạy trên remote.
- Bộ phiên bản: CI/setup-go lấy 1.22.8 từ `go.mod`, trùng WSL. Windows hiện dùng Go 1.26.5; kết quả local không thay thế race run trên Ubuntu 1.22.8.
- Lấy log workflow sau khi push: `gh run list --commit <commit>`, rồi `gh run view <run-id> --log-failed`. Chỉ kết luận nguyên nhân từ log thực tế.

## Điều tra Redis integration outage — 2026-11-22

- Nguyên nhân là timeout không được áp vào thao tác mạng. `AsyncRedisSync.flush` đã tạo context có timeout 150 ms và chuyển lỗi backend thành `Healthy=false`/tăng `FailedBatches`; limiter bỏ cache Redis khi unhealthy và tiếp tục dùng bộ đếm local. Nhưng `NewRedisClientBackend` tạo go-redis v9.7.3 với mặc định `ContextTimeoutEnabled=false`; trong cấu hình đó go-redis thay context của lệnh bằng `context.Background()` khi đọc/ghi socket. Redis mặc định đợi 3 giây để đọc phản hồi, trong khi test pause ghi 1.8 giây và chỉ đợi 1 giây. Lệnh bị pause vì vậy hoàn tất thành công sau khi Redis tiếp tục, không có lỗi để syncer đánh dấu degraded. Đây là mismatch timeout hiệu lực (nguyên nhân gần với mục c), không phải queue rỗng hay lỗi bị syncer nuốt.
- Đã bật `ContextTimeoutEnabled` ở Redis client, giảm timeout batch mặc định xuống 200 ms và thêm `Degraded()` accessor. Khi batch báo lỗi, `flush` giữ trạng thái degraded; limiter tiếp tục quyết định bằng counter local; batch Redis thành công kế tiếp đặt lại healthy. Test giữ nguyên các assertion outage/fallback/recovery, chờ trạng thái bằng polling và không skip khi Redis thiếu.
- Đã xác minh: `go test -tags=integration -count=1 -v ./edge/internal/ratelimit` PASS với Redis thật truy cập ở `localhost:6379`; outage được quan sát và recovery thành công. `go test -tags=integration -count=5 ./edge/internal/ratelimit` cũng PASS 5 lần liên tiếp.
- Lint sau gofmt: `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → PASS; `go test -count=1 ./...` → PASS.
- WSL đã được mở ngoài sandbox; Go 1.22.8 ở `/usr/local/go/bin/go` (không nằm trong PATH) và Redis báo `8.0.5`. Lệnh `/usr/local/go/bin/go test -tags=integration -race -count=5 ./edge/internal/ratelimit` → PASS trong 28.340s.
- Lệnh verbose cũng PASS trong WSL: `/usr/local/go/bin/go test -tags=integration -count=1 -v ./edge/internal/ratelimit`; cả Lua concurrent và outage/fallback/recovery đều PASS.
- Lệnh người dùng chạy trong WSL/Ubuntu (host này cần gọi Go qua path đầy đủ vì binary không nằm trong PATH): `/usr/local/go/bin/go test -tags=integration -race -count=5 ./edge/internal/ratelimit`.

## Cập nhật Compose storage

- Đã thay MinIO image không tồn tại bằng SeaweedFS S3 image `4.54` ghim digest; cập nhật biến S3 trong `.env.example`.
- CI Compose kiểm tra `docker compose config -q`, pull image không tùy chọn, rồi khởi động đợi healthcheck và dọn dịch vụ.
- Tag SeaweedFS `4.54` đã được xác nhận có trên Docker Hub API. `docker manifest inspect` không hoàn tất do kết nối registry bị đóng trong môi trường hiện tại.
- Đã chạy `docker compose -f deploy/docker-compose.yml config -q` → exit 0. Chưa xác minh `docker compose pull`/`make up`: sau khi cấp quyền truy cập Docker daemon, pull bắt đầu nhưng Docker Hub trả `failed to fetch anonymous token ... EOF` cho `postgres:17.4`, nên các image khác bị `Interrupted`. Chạy lại `docker compose -f deploy/docker-compose.yml pull` rồi `make up-wait` trên mạng/CI có thể truy cập Docker Hub.

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
- **Đã xác minh:** access/rate-limit tests gồm một triệu key tấn công với cap giữ nguyên; tràn capacity và đồng hồ lùi; X-Forwarded-For giả từ nguồn không tin cậy; IPv4-mapped IPv6; allow-list ưu tiên block/ban; GeoResolver lỗi theo `fail_mode`; ban hết hạn và cleanup; benchmark access/rate limit được ghi trong `docs/BENCHMARKS.md`.
- **Chưa xác minh:** race detector trên WSL/Ubuntu và benchmark request/edge; xem các lệnh tự chạy lại ở mục “Kiểm chứng gần nhất” phía trên.

### TODO P3

1. Chạy CI race trên runner Ubuntu để xác nhận data race bằng `go test -race -count=1 ./...`.
2. Chạy k6 với Redis service thật trong môi trường Docker có quyền truy cập daemon.
3. Kiểm thử GeoIP/ASN lookup với bộ MMDB hợp lệ được cấp phép; không commit dữ liệu MMDB vào repo.
4. Chuyển global blocklist từ biến môi trường sang danh sách có chữ ký đi cùng snapshot/ConfigSync; nối hook Under Attack với state/override từ CP.

### TODO

1. Bổ sung logic nghiệp vụ và test tích hợp khi bắt đầu phase tiếp theo.
2. Chọn DNS provider và hoàn thiện policy pháp lý trước khi mở dịch vụ cho khách thật.
