# Tiến độ

## Gate G — đóng nợ nền tảng P2–P5a — 2026-11-24

### Đã xác minh

- Line-ending policy: `.gitattributes` buộc LF cho repo và `.go`/`.sh`/`.yml`/`.yaml`/`.md`; `.editorconfig` cũng đặt `end_of_line = lf`. Đã chạy `git add --renormalize .`, sau đó stage riêng config để không gộp code chưa commit; commit riêng `bb6adda chore: enforce LF`. `git ls-files --eol` → `index: no i/crlf files`; `git diff --check` → exit 0. `.gitignore` bỏ qua `.env*` (giữ `.env.example`), file `.mmdb`, `.pem`/`.key`/`.p12`/`.pfx`, thư mục secrets và corpus ngoài.
- Cổng HTTP: `TestHTTPChallengeAndRedirect`, `TestHTTPRedirectRejectsUnknownHost`, `TestHTTPRedirectUsesCanonicalHostAndKeepsPathQuery` trong `edge/internal/listener/listener_test.go`; `TestCanonicalHTTPHostUsesRouterAndRejectsMalformedHosts` trong `edge/internal/edgecore/edge_test.go`. ACME callback vẫn chạy trước canonical host lookup; callback là ranh giới cấp token từ CP. Test kiểm tra unknown/malicious Host, canonical host/path/query và redirect 308. Kiểm tra này tìm ra lỗi thật `known.test:bad` từng bị chuẩn hóa thành `known.test`; `router.NormalizeHost` nay kiểm tra port số, range 0..65535, IPv6 bracket, và từ chối authority lỗi; `TestNormalizeHostRejectsMalformedAuthority` khóa hành vi.
- IP/header: `TestLoopbackProxyRewritesForwardingHeaders` kiểm tra XFF/X-Real-IP/X-Forwarded-* /Forwarded client bị xóa, Via/X-Request-ID/host header được edge đặt lại, hop-by-hop cùng header trong Connection bị gỡ. `TestUntrustedForwardedForDoesNotOverrideRemoteAddress` và `TestUntrustedForwardingHeadersCannotBypassIPPolicies` bao gồm XFF nhiều giá trị giả mạo trước allow/block, GeoIP và key rate limit. `TestAccessIPv4MappedIPv6AndAllowPrecedence`, `TestAccessGeoResolverErrorUsesSiteFailMode`, `TestTemporaryBanCleanupRemovesExpiredEntries`, `TestTemporaryBanExpiresAndRespectsCapacity` trong `edge/internal/access/access_test.go` khóa IPv4-mapped, thứ tự allow/block, Geo fail mode và dọn ban hết hạn. XFF hiện không được tin từ bất kỳ nguồn nào; IP chính sách lấy từ `RemoteAddr`/PROXY protocol.
- PROXY v1: `TestProxyProtocolV1OnlyFromTrustedCIDR` cùng test mới `TestProxyProtocolV1RejectsMalformedTruncatedAndOversizedHeaders`, `TestProxyProtocolV1MalformedConnectionDoesNotStopAccepting` và `TestProxyProtocolV1IsIgnoredFromUntrustedSource` trong `edge/internal/listener/listener_test.go`. Parser giới hạn 108 byte, yêu cầu CRLF, đúng family/địa chỉ/port, deadline, bỏ kết nối sai mà không làm dừng `http.Server.Serve`.
- Reverse proxy: `TestLoopbackProxyHTTP1HTTP2SSEAndWebSocket`, `TestLoopbackSSEFlushesBeforeOriginCompletes`, `TestLoopViaRejected`, `TestLoopbackProxyRewritesForwardingHeaders`; test mới `TestRetryTransportNeverRetriesAfterRequestBodyWasSent`, `TestRetryTransportRetriesGetAndHeadOnlyForDialErrors`, `TestProxyErrorsCarryRequestIDAndDoNotReflectTransportDetails` trong `edge/internal/proxy/proxy_test.go`. Kiểm tra header lỗi 502/504 có request ID và không phản chiếu lỗi transport.
- Body WAF/rules: `TestBodyInspectionReadsOnceAndReplaysOriginalBytes`, `TestBodyPrefixCapStreamsRemainderAndPreservesFraming`, `TestGzipBodyIsInspectedBoundedlyAndRawBytesReplayToOrigin`, `TestGzipExpansionAndUnsupportedEncodingAreMarkedTruncated` trong `edge/internal/reqctx/body_test.go`; `TestLoopbackInspectedChunkedBodyTrailerAndExpectContinueReachOrigin` trong `edge/internal/edgecore/edge_test.go`; deadline slow/hung/truncated hiện có `TestLoopbackBodyReadDeadlineSlowAndHungClients`, `TestLoopbackTruncatedBodyReleasesListener`. Gzip được giải nén trong giới hạn byte/tỷ lệ; encoding không hỗ trợ đánh dấu truncated; origin nhận raw body/framing.
- P5a hồi quy hiện hữu: `TestFingerprintIndependentFoxIOChromeCapture`, `TestFingerprintIndependentFoxIOTLS12ALPNCapture`, `TestClientHelloAcrossTLSRecordsAndOver16KiBCap`, `FuzzFingerprintClientHello`, loopback timeout trong `edge/internal/listener/fingerprint_test.go`; pool isolation/reset trong `edge/internal/reqctx/pool_test.go`; async DNS/cache ở `TestVerifiedResolverAsyncBoundedDeduplicatedAndNonblocking`, `TestVerifiedResolverNegativeCacheAndCapacity`, `TestVerifiedBotBypassesChallengeAndFreeHasNoChallengeEntitlement`; cookie/PoW/rate/body challenge ở `TestChallengeCookieBindingExpiryRotationAndReplay`, `TestChallengeVerifyHandlerRejectsBadProofAndSetsCookie`, `TestChallengeVerifyRateLimitMethodBodyAndRequestID`, `TestLoopbackChallengeVerifyBodyReadDeadline` (`edge/internal/bot/bot_test.go`). Không viết lại các test này.
- Wafcore: fixture round-trip đã có ở `TestSnapshotYAMLRoundTrip` và golden vị trí DSL ở `TestDSLErrorGolden` trong `pkg/wafcore/wafcore_test.go`. Test mới `TestLegacySnapshotMissingOptionalFieldsUsesSafeZeroValues` và `TestSnapshotUnknownFieldsAreIgnoredForYAMLAndJSON` xác nhận snapshot cũ nhận zero-value và decoder bỏ qua field chưa biết theo `docs/DECISIONS.md`. Danh sách schema P1–P5a được thêm ở `docs/control-plane.md` mục 5.8; P5a không thêm field schema.
- Benchmark WSL Linux, Go 1.26.11, Intel Core i5-11400H, GOMAXPROCS=12, `-benchtime=1000x -benchmem`: `BenchmarkAccessCheck` 200.7 ns/op, 17 B/op, 1 alloc; `BenchmarkRateLimitAllow` 901.2 ns/op, 298 B/op, 7 allocs; `BenchmarkWAF` 6,986 ns/op, 6,191 B/op, 26 allocs. Kết quả ghi tại `docs/BENCHMARKS.md`; số Windows lịch sử được đánh dấu không dùng làm bằng chứng.
- Công cụ/CI: k6 script `test/k6/ratelimit.js` đã có; hướng dẫn thêm ở `docs/data-plane.md` §5.5. `TestMMDBFilesWhenOperatorDatabasesAreConfigured` skip nếu không có file được cấp; cách lấy GeoLite2 và đặt env ngoài repo được ghi tại §5.5. Workflow vẫn có job lint, race, govulncheck bắt buộc, Redis integration có service và Compose độc lập; ClickHouse/SeaweedFS chuyển sang profile riêng; bước CI chạy gofmt/tidy rồi `git diff --exit-code`.

### Chưa xác minh — lệnh chạy lại

- Đã xác minh WSL Go 1.26.11: `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go build ./...` → exit 0; `go test -count=1 ./...` → PASS; `go test -race -count=1 ./...` → PASS (chạy lại sau sửa listener cuối); `govulncheck ./...` → `No vulnerabilities found.`. Redis localhost thật: `REDIS_ADDR=127.0.0.1:6379 go test -tags=integration -race -count=5 ./edge/internal/ratelimit` → `ok ... 31.136s`.
- `docker compose -f deploy/docker-compose.yml config -q` → exit 0 trên Windows Docker CLI 29.1.2; không thể chạy pull/up vì Docker Desktop Linux engine không khởi động/không có pipe, và WSL không có Docker CLI. GitHub Actions chưa chạy trên commit mới; không tuyên bố CI xanh. `git diff --exit-code` sau gofmt/tidy được cấu hình trong job lint; không chạy local trên working tree còn các thay đổi phase chưa commit.
- k6 chưa xác minh vì `k6` không có trong PATH (`k6 version` báo command not found); lệnh chạy ở `docs/data-plane.md` §5.5. MMDB test `TestMMDBFilesWhenOperatorDatabasesAreConfigured` → `SKIP` do chưa cấp file GeoLite2 (cần tài khoản MaxMind); test giả và lỗi mở file vẫn chạy.
- Loopback cần chạy ngoài sandbox Windows; đã chạy trong WSL Ubuntu và toàn bộ full race suite ở trên PASS.

### Nợ kỹ thuật

- **TODO-G-1:** PROXY protocol v2 chưa triển khai. Repo hiện chỉ cấu hình v1; chưa có NLB/v2 contract cụ thể. Cần fixture/header v2 chuẩn và quyết định CRC32C/LOCAL trước khi thêm parser; hiện test v1 malformed/untrusted/length giới hạn đã có.
- **TODO-G-2:** chưa có test chạy với GeoLite2 MMDB thật nếu không có file cấp phép; test giả và lỗi mở file đã có.
- **TODO-G-3:** chưa xác nhận GitHub Actions xanh sau commit/push; local test không thay thế kết quả CI.
- **TODO-P4f-1** còn mở: benchmark WAF concurrency 200 vẫn từng cho p99 >1 giây và work cap chạm 100%, dù full race Gate G hiện PASS. Cần hoàn tất đánh giá tải cao/clean fail-closed trước khi tuyên bố an toàn overload.

### Rà soát `//nolint` không-test

- Có 11 vị trí hiện hữu, không thêm mới: `edge/cmd/edge/main.go:207,237,264` (G304: path do operator cấu hình; `TestLoadSampleYAMLSnapshotNeedsExplicitDevelopmentFlag`, `TestLoadChallengeKeyringRequiresStrongAndSelectableKeys`); `edge/internal/configsync/holder.go:42,44,79,114` (G304: snapshot/keyring file path từ cấu hình; `TestLoadPublicKeysFromEnvAndFile`, `TestApplySignedSnapshot`); `edge/internal/listener/fingerprint.go:4,277` (G401 JA3 bắt buộc MD5 không dùng làm xác thực; hai test vector độc lập JA3/JA4); `edge/internal/proxy/proxy.go:138` (G115: modulo total positive, không vượt max int; `TestWeightedOriginSelectionCounterNearUint64Maximum`); `edge/internal/proxy/proxy.go:257` (G706 false positive trên RequestID đã lọc hex và log `%q`; `TestProxyErrorDoesNotLogOrReflectUnsafeRequestID`). Kỳ vọng chỉ một nolint G706 không đúng với repo hiện tại; các suppression G304/G401/G115 đã tồn tại và có lý do/test nêu trên.

### Quét an toàn

- Không tìm thấy `http.Redirect` trong edge; cổng :80 tạo absolute URL từ canonical host do router trả về. `RequestID` sinh bằng 16 byte ngẫu nhiên rồi hex; không đọc X-Request-ID client. `TestLoopbackEdgeGeneratesRequestIDAndIgnoresClientHeader` kiểm tra điều này; log edge dùng `%q` cho request ID và panic value; proxy lỗi không phản chiếu chi tiết transport.
- Không tìm thấy `defer Close()` bị bỏ qua ở đường ghi file. `configsync.persist` kiểm tra `Write`, `Sync`, `Close` trên success và error branches trước atomic rename. Đã rà ép kiểu nhạy tràn: rate limiter có test clock rollback/extreme refill; punycode có test miền 0..35 và biên; host port validation có test range; proxy origin counter có test gần `uint64` wrap. Những ép kiểu còn lại là parse/copy có trần hoặc giới hạn bởi cấu trúc dữ liệu.

## P5a — hardening fingerprint, RequestCtx, bot resolver và challenge — 2026-11-24

### Đã xác minh

- Fingerprint parser ghép ClientHello qua tối đa 16 TLS handshake record; giới hạn hello 16 KiB và record capture 64 KiB. Deadline peek cố định 3 giây được gỡ khi hello hoàn chỉnh. Cả hai raw vector độc lập trong `testdata/fingerprints/` khớp JA3/JA4 kỳ vọng; test malformed/truncated, over-16-KiB, GREASE/extension lặp, fragmentation và trần số record đều PASS.
- Test loopback `TestLoopbackSlowClientHelloTimeoutReleasesConnections` gửi 16 kết nối với ClientHello dở dang, kiểm tra giới hạn connection/IP, mọi kết nối được dọn, số goroutine tăng không quá 4 và heap sau GC không tăng quá 8 MiB. `TestLoopbackChallengeVerifyBodyReadDeadline` xác minh body verify chậm trả JSON 408 có request ID, handler/writer được giải phóng. Các test loopback này chỉ chạy ngoài sandbox Windows; đã chạy trong WSL Ubuntu.
- `RequestCtx.Release` zero toàn struct. Test reflection dirty mọi field và thất bại nếu thêm struct field không thể dirty; danh sách miễn trừ field connection hiện rỗng. `New` reset trước khi áp fingerprint. Pool stress 40 goroutine × 200 vòng chạy dưới race detector.
- Verified bot DNS chuyển cache miss sang queue 128, 8 worker mặc định, 100 lookup/giây, timeout 300 ms, cache dương/âm bounded 10.000 / TTL 10 phút. Miss luôn “chưa xác minh”, reverse DNS cần forward-confirm. Test resolver giả kiểm tra 10.000 IP User-Agent Googlebot không block request, trần đồng thời/rate, singleflight, negative cache, forward mismatch và 1 triệu địa chỉ với cache cap.
- State hành vi bot chia 32 shard, cap 100.000, TTL 10 phút; khi cap đầy key mới tiếp tục được đánh giá stateless và không ghi counter mới. Test sinh 1 triệu IP xác nhận cap; test kiểm tra expiry/reinit.
- Challenge API/XHR nhận JSON máy đọc được với request ID; navigation GET/HEAD `Accept: text/html` nhận HTML có CSP nonce, `no-store`. `/__waf/verify` POST-only, IP rate limit 20/phút, body cap 8 KiB, read/process timeout 1 giây; cookie có Secure/HttpOnly/SameSite=Lax/Path=/, không Domain. Test HMAC/PoW/replay/rotation/verified-bot bypass/Free entitlement được giữ và chạy lại.
- WSL Ubuntu, Go 1.26.11: `go test -race -run TestLoopbackSlowClientHelloTimeoutReleasesConnections -count=1 -v ./edge/internal/listener` → PASS; `go test -race -run TestLoopbackChallengeVerifyBodyReadDeadline -count=1 -v ./edge/internal/bot` → PASS.
- Fuzz final parser: `go test -run ^$ -fuzz FuzzFingerprintClientHello -fuzztime=60s ./edge/internal/listener` → PASS, 2,637,817 executions trong 60.141 s, không panic.
- Benchmark WSL/Linux (Intel Core i5-11400H, Go 1.26.11, `-benchtime=1000x -benchmem`): parser-only 5,829 ns/op, 818 B/op, 44 allocs/op; bounded peek + compute 9,854 ns/op, 4,068 B/op, 94 allocs/op. Đã ghi ở `docs/BENCHMARKS.md`.
- Vector nguồn: FoxIO JA4 pcap commit `4ab8e3f18f4b27e0b896c4ec2c251e20506eb87e` (SHA-256 file được so đúng); expected đối chiếu community project commit `797a8b074e135f659da1ee3193b5a4cc111dfc26` và Salesforce JA3 commit `502cc6395811c54743b0561419d61900a6df3ff7` / dpkt v1.9.1. Mỗi test ghi URL + commit trong comment.
- WSL Ubuntu, Go 1.26.11: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...` → `0 issues.` (chạy lại sau thay đổi cuối); `go vet ./...` → exit 0; `go build ./...` → exit 0; `go test -count=1 ./...` → PASS tất cả package; `go run golang.org/x/vuln/cmd/govulncheck@v1.10.0 ./...` → `No vulnerabilities found.` (chạy lại sau thay đổi cuối).
- Các package đã đổi (`bot`, `edgecore`, `listener`, `reqctx`) PASS `go test -race -count=1`. Full `go test -race -count=1 ./...` **FAIL trong cả hai lần thử** ở test tải có sẵn `edge/internal/waf/TestWAFParallel50GOMAXPROCSMatrix`: lần 1 `gomaxprocs_12`, lần 2 `gomaxprocs_2`; mỗi lần `clean fail-closed requests rejected=1/250`. Đây là lỗi P4f ngoài phạm vi P5a; không sửa/loại test. Vì race toàn repo còn đỏ, P5a chưa được đánh dấu hoàn tất.
- `git diff --check` → exit 0; chỉ cảnh báo Git rằng một số working-copy CRLF sẽ được chuẩn hóa LF.

### Chưa xác minh / cần chạy lại

- Chưa xác nhận GitHub Actions sau commit/push. Loopback tests cần môi trường ngoài sandbox Windows; đã xác minh cục bộ trong WSL. Để tái hiện race failure P4f và kiểm tra run mới sau khi xử lý TODO-P4f-1:

```sh
go test -race -count=1 ./...
go test -race -count=5 ./edge/internal/waf -run '^TestWAFParallel50GOMAXPROCSMatrix$'
```

- Trên Windows sandbox, loopback bị chặn (WinSock “access to a socket … forbidden”); WSL chạy được qua `/usr/local/go/bin/go` (Go 1.26.11). `wsl.exe -l -q` bị AccessDenied trong sandbox, nhưng lệnh WSL được chạy ngoài sandbox đã PASS cho các test loopback kể trên.

### Nợ kỹ thuật

- **TODO-P5a-1:** PoW replay cache vẫn riêng từng edge; chưa chống replay proof xuyên edge.
- **TODO-P5a-2:** chưa có feed sản xuất cho IP/ASN/Tor hoặc vendor prefix; `IPReputation`/prefix remain operator adapters.
- **TODO-P5a-3:** cấp/rotate HMAC keyring qua mTLS thuộc P6b; hiện keyring operator/env hoặc interface, thiếu key khi entitlement bật là startup error.
- **TODO-P5a-4:** net/http không giữ thứ tự header wire nên tín hiệu thứ tự header chưa được chấm.
- **TODO-P5a-5:** hai raw ClientHello source độc lập đã có; bộ vector vẫn chỉ có hai mẫu, chưa bao phủ rộng nhiều client/phiên bản TLS.
- **P4f status:** TODO-P4f-1 vẫn mở; tải 200 goroutine từng đo p99 1.603 s và work cap chạm 100%, chưa đủ bằng chứng để đóng khả năng overload fail-closed.
- **Gate G status:** phần code/test được tìm thấy: ACME HTTP-01 trước canonical redirect (`TestHTTPChallengeAndRedirect`), forged XFF bị xóa và IP transport được đặt lại (`TestLoopbackProxyRewritesForwardingHeaders`), `.gitattributes` đặt `eol=lf`. Chưa coi đây là test CI mới độc lập ngoài những test hiện hữu.
- Inventory `//nolint` trong code không-test (11 vị trí; không thêm vị trí mới): `edge/cmd/edge/main.go:207,237,264`; `edge/internal/configsync/holder.go:42,44,79,114`; `edge/internal/listener/fingerprint.go:4,277`; `edge/internal/proxy/proxy.go:138,257`.

## P4f — ngân sách WAF theo work và suy giảm quá tải — 2026-11-24

### Đã xác minh

- Thay 2 ms đồng hồ tường bằng work caps theo gói (Free 128 KiB/256 normalize steps/128 regex windows; Pro 256 KiB/512/192; Business 384 KiB/768/256; Enterprise 512 KiB/1.024/384). Khi hết trần, tag `waf_work_exhausted` + `waf_scan_truncated`; body có thêm truncation và áp fail-mode. Timeout đọc body được tách riêng khỏi `waf_budget_exceeded`.
- `budget_ms` là cầu chì wall-clock mặc định 100 ms, cấu hình 1–5.000 ms; ngưỡng được bù theo backlog WAF/GOMAXPROCS và có trần 5 giây. `waf_budget_exceeded` chỉ từ cầu chì. Overload levels dựa trên backlog ước lượng, EWMA WAF và rolling 64-request fuse ratio: bỏ paranoia >1 → chia đôi work cap → chỉ cuối cùng áp fail-mode khi persistent fuse ratio cao và backlog hạ. Có accessor metrics `Phase.Metrics()`, counter audit Prometheus và log chuyển tier.
- Test WSL Linux `TestWAFParallel50ReportsP99AndBudgetAction`: 50 goroutine × 5 (250) request, p50 **5,584,535 ns**, p99 **63,856,855 ns**, fuse **0/250**, clean FPR **0/20**, payload SQLi đầu body bị block **50/50**; GOMAXPROCS=12/12 CPUs. Test fail-closed clean load ở GOMAXPROCS=2/4/12: mỗi cấu hình **0/250** clean rejects, **0/250** fuse. Work-cap unit test cũng xác minh cap không bị gắn nhầm `waf_budget_exceeded`.
- Đã chạy ma trận Linux/WSL `BenchmarkWAFLoadMatrix`, 200 request/cell, body 8/64/256 KiB, repeated Aho, deep JSON, multipart, 200 params, concurrency 1/10/50/200; CPU i5-11400H 6C/12T, Go 1.26.11, GOMAXPROCS 12. Số tóm tắt p50/p99, allocs/op, work-cap/fuse % được ghi ở [BENCHMARKS.md](BENCHMARKS.md). Mức xấu nhất quan sát p99 **1,602,541,791 ns**, work-cap đến **100%**, fuse đến **9%** ở 200 goroutine.
- Đã sửa docs để nói chính xác body over-cap chỉ quét prefix đã buffer; không đọc/quét tail thật. Free fail-open vẫn có padding bypass risk; mitigation đã ghi: truncation anomaly +3, cap Content-Length theo content type, và rate-limit chặt body lớn.

- WSL Ubuntu, Go 1.26.11: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go test -count=1 ./...` → PASS toàn bộ package; `go test -race -count=1 ./...` → PASS toàn bộ package (waf 19.158s, ratelimit 4.661s). Không có test đỏ.
- `TestWAFParallel50ReportsP99AndBudgetAction` và `TestWAFParallel50GOMAXPROCSMatrix` chạy lại sau thay đổi: 50 goroutine × 5; clean 0/250 reject và 0/250 fuse ở GOMAXPROCS 2, 4, 12; 50/50 SQLi prefix bị chặn. Output cụ thể và máy đo đã ghi bên trên.
- `git diff --check` → PASS.

### Chưa xác minh — lệnh tự chạy lại

- Chưa chạy integration Redis riêng sau P4f (không sửa ratelimit); chưa chạy GitHub Actions sau commit/push. Có thể tự chạy trong WSL/Linux:

```sh
golangci-lint run ./...
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
go test -tags=integration -race -count=5 ./edge/internal/ratelimit
```

### Nợ kỹ thuật

- **TODO-P4f-1:** benchmark tải 50/200 goroutine cho thấy p99 worst-case vượt 1 giây; work cap chạm tối đa 100%, fuse còn chạm đến 9%. Với fail-closed, request hợp lệ bị cắt bởi cap/fuse vẫn có thể bị từ chối. Cần hiệu chỉnh work units/overload thresholds dựa trên profile Linux và xác nhận tỷ lệ reject sạch dưới tải trước khi tuyên bố an toàn tải cao. Hiện test fail-closed sạch đã chứng minh 50 goroutine với workload 8 KiB, không chứng minh upload 64–256 KiB ở 200 goroutine.
- **TODO-2:** audit writer còn in-memory, chưa bền qua restart.
- **TODO-3:** body read deadlines đã xác minh WSL P4e; không thay đổi trong P4f.

## P4e — WAF buffer bypass và deadline đọc body — 2026-11-24

> Historical P4e validation below predates P4f; P4f supersedes the 2 ms wall-clock budget and body-read timeout tagging semantics.

### Đã xác minh

- Luồng WAF thay trần 4 KiB/request, 2 KiB/target và 1 KiB body prefix bằng body cap theo gói (Free 8 KiB, Pro 64 KiB, Business 128 KiB/256 KiB theo entitlement, Enterprise 256 KiB), tối đa 256 KiB/target và 1 MiB/request. Aho-Corasick quét toàn phạm vi; body normalize theo block 4 KiB chồng 512 byte; RE2 chỉ chạy trên cửa sổ 512 byte quanh keyword, tối đa 128 cửa sổ/request và giữ head/tail khi vượt K.
- Validation snapshot cho phép `scan_limit_bytes` đến 1 MiB, giới hạn `body_limit_kb`/`max_body_bytes` ở 256 KiB; test xác nhận entitlement lớn không nới cap Free 8 KiB.
- Cắt phần quét gắn cờ `waf_body_truncated` (body, mặc định +3 điểm) hoặc `waf_scan_truncated` (target/window) và áp fail mode; test kiểm chứng payload sau 1/2/8/60 KiB đệm ở path/query/header/cookie/form/JSON/XML/multipart, giữa/cuối. Payload trong cap bị bắt; payload sau package cap đi vào fail mode, không thành kết quả sạch.
- Đọc body đặt `http.ResponseController.SetReadDeadline` trước khi pipeline đọc; mặc định 1 giây, override qua `body_read_timeout_ms`. Timeout gắn `waf_budget_exceeded`, `waf_body_truncated`, `waf_body_read_timeout`; deadline hết hạn được giữ lại để proxy không treo trên phần request chưa đọc. Có test loopback slow/hung/truncated body; các test này chỉ chạy ngoài sandbox Windows (WSL/Linux).
- FPR test thêm 30 mẫu body lớn sạch cho mỗi paranoia (JSON, form, multipart, text); benchmark/test in FPR từng P1–P4. Có test tải 50 goroutine, đo p50/p99 và kiểm tra request vượt budget áp fail mode; test heap 3.000 request giữ nguyên để phát hiện tăng bộ nhớ.
- Script `scripts/measure-waf-corpus.sh <dir>` đọc corpus ngoài chỉ từ thư mục người dùng chỉ định, in TPR theo nhóm và không thay đổi luật.
- **Đã xác minh trong WSL Ubuntu/Linux, Go 1.26.11:** `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go test -count=1 ./...` → PASS tất cả package; `go test -race -count=1 ./...` → PASS tất cả package. `sh -n scripts/measure-waf-corpus.sh` và `git diff --check` → PASS.
- WSL verbose test xác nhận FPR body sạch lớn 0/30 (0%) riêng cho P1, P2, P3, P4; 50 goroutine × 5 request ghi p50 2,090,501 ns / p99 22,048,227 ns, budget exceeded 250/250 và tất cả decision fail-closed có tag `waf_budget_exceeded`.
- Test loopback WSL: `TestLoopbackBodyReadDeadlineSlowAndHungClients` PASS (slow/hung kết thúc lần lượt ~110/100 ms với timeout cấu hình 80 ms); `TestLoopbackTruncatedBodyReleasesListener` PASS. Full race suite cũng xác minh test listener `TestPerIPConnectionLimit`.
- Benchmark WSL/Linux `-benchtime=100x -benchmem`: p99 body/query nằm khoảng 676,028–2,379,751 ns; body keyword lặp/multipart và các body 64/256 KiB vượt 2 ms ở 100% lần đo, gắn budget tag và đi theo fail mode. JSON lồng sâu 8 KiB không vượt budget. Đủ số p50/p99, B/op, allocs/op đã ghi trong `docs/BENCHMARKS.md`; test heap 3.000 request PASS (heap tăng không quá 4 MiB).
- 64 ca matrix bypass ở path/query/header/cookie/form/JSON/XML/multipart với padding 1/2/8/60 KiB, middle/end PASS; test payload cuối body sau >128 cửa sổ tiền lọc PASS; package cap Free/Pro áp dụng fail mode như kỳ vọng.

### Chưa xác minh — lệnh tự chạy lại

- Không còn test/lint/vet nội bộ chưa chạy trong môi trường hiện tại. Loopback không chạy được trong sandbox Windows; đã xác minh lại bằng WSL/Linux như trên. Sau thay đổi tiếp theo, lệnh đầy đủ: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./... && go vet ./... && go test -count=1 ./... && go test -race -count=1 ./...`.
- Chưa chạy lại GitHub Actions sau commit/push; local WSL không thay thế xác nhận CI.
- Chưa có corpus v3 độc lập do người dùng cung cấp. Khi có, chạy `sh scripts/measure-waf-corpus.sh /path/to/corpus-v3`; corpus v2 vẫn là dev, không held-out.

### Nợ kỹ thuật

- **TODO-2:** audit writer đang in-memory; event enqueue bounded/nonblocking và có count timeout/truncation/budget, nhưng chưa bền vững qua restart. Thay adapter tại P6a.
- **TODO-3: đã xử lý và xác minh trong WSL P4e:** đặt read deadline trên kết nối HTTP thực và kiểm tra slow/hung/truncated body bằng loopback; không còn dựa vào deadline WAF 2 ms để ngắt socket.
- **TODO P4e-1:** body lớn hơn cap không thể quét đuôi thật mà vẫn chỉ buffer prefix và stream phần dư nguyên trạng; phần vượt cap được đánh dấu thiếu quan sát và áp fail_mode. Nếu yêu cầu quét đuôi thật ngoài phạm vi cap, cần thiết kế bounded spool/replay riêng trước khi triển khai.

### Lệnh tự chạy lại

```sh
golangci-lint run ./...
go vet ./...
go test -race -count=1 ./...
go test -run '^$' -bench '^BenchmarkWAFWorstCase$' -benchtime=100x -benchmem ./edge/internal/waf
```

## P8 — fingerprint TLS và bot challenge — 2026-11-23

### Đã xác minh

- WSL Ubuntu / Go 1.26.11: `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go build ./...` → exit 0; `go test -count=1 ./...` → PASS; `go test -race -count=1 ./...` → PASS. Các bài test loopback/TLS chạy trong WSL; Windows sandbox chặn kết nối localhost nên không dùng kết quả Windows cho chúng.
- Thêm capture thụ động tối đa 16 KiB trên net.Conn trước TLS, chuyển nguồn fingerprint qua `http.Server.ConnContext`, gán JA3/JA4 vào `RequestCtx`. Parser bỏ GREASE, tạo JA3 MD5 tương thích chuẩn và JA4 theo định dạng FoxIO; lỗi/truncated/malformed để trống. Golden test cho fixture Go-like, curl-like, browser-fake; test junk/cắt ngắn; HTTPS loopback chứng minh fingerprint thực đến RequestCtx.
- Bot score clamp 0–100, có tín hiệu UA thư viện/headless/rỗng và giả danh crawler, thiếu Accept/Accept-Language, interface reputation IP/ASN, interface fingerprint automation, tốc độ 10 giây, 404, đường dẫn số tuần tự, thiếu cookie đã ký và kết quả challenge trước đó; bảng map hành vi có trần 100.000 key. Verified bot dùng reverse DNS → suffix Google/Bing/DuckDuckGo → forward DNS equality, cache TTL/cap, hoặc prefix IP được operator cấp.
- JS challenge tại `/__waf/verify`: PoW SHA-256 difficulty 1–24 (mặc định 18), ticket 5 phút dùng một lần trong replay cache giới hạn từng edge, cookie HMAC-SHA256 30 phút ràng buộc site/UA hash/IPv4 /24 hoặc IPv6 /64; key ID hỗ trợ key cũ khi xoay. Test false/expired/wrong-UA/wrong-/24 cookie, PoW sai, replay, old key, endpoint, cookie bypass, verified bot bypass và entitlement Free.
- Keyring có interface `bot.KeyRing`; snapshot chỉ giữ `challenge_hmac_key_id` theo contract control-plane. Adapter env nhận `EDGE_CHALLENGE_HMAC_KEYS` với key base64 tối thiểu 32 byte, không log khóa; bật entitlement mà thiếu keyring thì process lỗi cấu hình rõ ràng. Turnstile có `CaptchaVerifier` interface/stub từ chối mặc định.
- Mọi test loopback liên quan có tên `TestLoopback...`; sandbox Windows không cho kết nối tới địa chỉ loopback, vì vậy các test này chỉ chạy được ngoài sandbox Windows hoặc trong WSL/Linux.

### Chưa xác minh — lệnh tự chạy lại

- Chưa chạy Govulncheck (không thay đổi dependency); lệnh: `govulncheck ./...`.
- Chưa có linter binary cài sẵn; lần xác minh dùng `go run github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.15.0 run ./...`.
- Chưa tích hợp nguồn uy tín ASN/Tor/vendor range sản xuất; interface có thể nối adapter. Thứ tự header không thể lấy từ `http.Request.Header` vì net/http chỉ cung cấp map đã parse.
- Chưa có adapter phân phối/rotate keyring tự động qua mTLS CP↔edge; operator hiện phải provision env hoặc inject `bot.KeyRing`.

### Nợ kỹ thuật

- **TODO P8-1:** replay cache proof nằm trong bộ nhớ từng edge; muốn ngăn cùng proof dùng trên edge khác cần shared bounded replay store.
- **TODO P8-2:** net/http không giữ thứ tự wire của header; bổ sung parser quan sát được thứ tự mà vẫn phòng request smuggling nếu cần dùng tín hiệu này.
- **TODO P8-3:** nối `bot.KeyRing` với luồng phân phối bí mật qua mTLS; giữ key ID cũ ít nhất 30 phút sau khi ngừng ký.
- **TODO P8-4:** adapter ASN/Tor/verified-bot prefix do operator/CP cung cấp và Turnstile thật chưa được triển khai. JS challenge chỉ làm bot đơn giản tốn chi phí hơn, không chặn bot chạy trình duyệt thật.

### Lệnh tự chạy lại

```sh
golangci-lint run ./...
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
```

## P4d — giới hạn scan và coverage dev — 2026-11-23 (lịch sử; P4e supersedes các trần scan)

### Đã xác minh

- WAF quét theo thứ tự path/URI → query → header chọn lọc → cookie → body; giới hạn hiện hành 4 KiB/request, 2 KiB/mục tiêu và 1 KiB body prefix, query parse tối đa 8 KiB/64 tham số. Kiểm tra deadline đặt giữa targets, normalize và mỗi nhóm bốn rule; điểm đã cộng được giữ khi hết budget.
- Body prefix được buffer hữu hạn và phát lại cùng phần dư chưa đọc; body bị cắt, không được quét hoặc đọc lỗi gắn `waf_body_truncated` và cộng điểm mặc định 3 (cấu hình 1–5; 0/bỏ trống dùng mặc định). Test xác nhận body 256 KiB có SQLi ngay prefix vẫn bị phát hiện và origin nhận đủ body; trường hợp body bị bỏ qua không bị đọc. Test body 8/64/256 KiB, 200 tham số, Aho lặp, JSON sâu, multipart xác minh hành động fail-open/fail-closed khi hết ngân sách.
- Audit sink enqueue không chặn, queue bounded; in-memory writer đếm `waf_budget_exceeded`/`waf_body_truncated`, queue đầy tăng drop counter. Đây chưa phải lưu trữ bền vững.
- v2 được relabel thành **dev**, không còn gọi là held-out. Sau P2 TPR dev/FPR dev ghi tại `docs/BENCHMARKS.md`: P2 tăng SQLi 55→70%, RCE 35→45%, traversal 50→62.5%, deserialization 27.5→40%, XSS 90→100%, RFI 65→90%, SSRF 80→90%; P3/P4 không tăng trên v2. FPR 0/330 ở cả P1–P4.
- Mutation tự sinh từ cả hai trạng thái: mẫu gốc đã bắt 820/841 (97.5%), mẫu gốc lọt 61/435 (14.0%). Đây chỉ là dev/mutation, không thay held-out. Test in toàn bộ v2 miss và mutation miss.
- Đã xác minh trên Windows Go 1.26.11: `go test -count=1 ./edge/internal/waf ./edge/internal/pipeline ./pkg/wafcore` → PASS; test P4d paranoia/body-limit/large-prefix/worst-shape và corpus/mutation đều PASS, FPR 0/330 P1–P4.
- Windows/amd64 Go 1.26.11: `golangci-lint run ./...` → `0 issues.`; WSL/Linux Go 1.26.11: `go vet ./...` → exit 0, `go test -count=1 ./...` → PASS mọi package, `go test -race -count=1 ./...` → PASS mọi package. Test loopback được xác minh trong WSL ngoài sandbox.
- Benchmark WSL sau cap mới: tất cả workload đo 100 lần có p99 <2 ms; max là 1,879,880 ns/op cho 200 query params. Body 8/64/256 KiB, Aho lặp, JSON sâu, multipart: p99 tối đa 728,953 ns/op. Chi tiết `ns/op`, p50/p99, B/op, allocs/op ở `docs/BENCHMARKS.md`.

### Chưa xác minh — lệnh tự chạy lại

- Không còn phép kiểm tra mã nào đang chờ trong môi trường hiện tại; lệnh bên dưới để người dùng chạy lại hoặc xác minh trên môi trường triển khai.
- Corpus v3: chưa có. Khi người dùng cung cấp hai file `attacks.tsv`/`clean.tsv`, chạy `WAF_CORPUS_DIR=/path/to/corpus-v3 go test -count=1 -v ./edge/internal/waf -run '^TestWAFCorpusMetrics$'`; test không nạp luật từ thư mục corpus.

### Nợ kỹ thuật

- **TODO-2:** thay in-memory audit writer bằng telemetry bền vững ở P6a; hiện audit mất khi process dừng và queue đầy thì sự kiện bị drop có counter.
- **TODO-3:** giới hạn wall-clock khi đọc body từ client chậm. Buffer có trần byte nhưng `io.ReadAll` qua `Request.Body` có thể chờ Read; deadline WAF hiện kiểm tra sau lệnh đọc và không thể tự ngắt socket. Cần listener/server read deadline trước khi khẳng định hard wall-clock bound.
- Các benchmark workload thử nghiệm đạt p99 dưới 2 ms trên máy WSL này; đây không phải real-time guarantee cho mọi máy/traffic. `Request.Body` vẫn có thể chờ client chậm.
- Corpus v2 tự viết và đã bị nhìn thấy; TPR/FPR chỉ là dev. Held-out độc lập chỉ có sau khi người dùng cấp v3.

### Lệnh tự chạy lại

```sh
go test -count=1 -v ./edge/internal/waf -run '^(TestWAFCorpusMetrics|TestAttackMutations)$'
go test -run '^$' -bench '^BenchmarkWAFWorstCase$' -benchtime=100x -benchmem ./edge/internal/waf
golangci-lint run ./...
go vet ./...
go test -race -count=1 ./...
```

## P4c — hồ sơ trước khi corpus v2 được relabel — 2026-11-23

> Lịch sử dưới đây ghi trạng thái tại P4c. P4d bên trên thay thế các kết luận hiện hành: corpus v2 là dev, không phải held-out; các số TPR/FPR và mutation đã được đo lại sau thay đổi luật. Không dùng nội dung lịch sử này như trạng thái hiện tại.

### Đã xác minh

- Lúc P4c, v2 được gọi held-out; theo cập nhật yêu cầu, bộ 480 attack và 330 clean đó nay được relabel dev, baseline held-out đã xóa. V1 đã được xem để bổ sung luật nên cũng không độc lập.
- Kết quả P4c cũ được giữ để truy vết trong `docs/BENCHMARKS.md`, không phải số xác minh hiện hành. P4d đã đo lại và ghi TPR/FPR dev theo paranoia.
- Mutation test sinh 347 biến thể từ dev, bắt 347/347 (100%) ở các phép biến đổi còn giữ ngữ nghĩa. Test sẽ in đầy đủ danh sách miss nếu kết quả đổi.
- Sáu rule bổ sung có test dương và âm riêng. Test input xấu xác minh body chính xác 8/64/256 KB đi qua fail-mode khi trễ quá 2 ms; test hình dạng 200 tham số, keyword Aho lặp, JSON lồng sâu, multipart nhiều phần xác minh budget/fail-mode. Test 3.000 request sau warm-up giữ heap tăng dưới 4 MiB.
- Benchmark WAF đã chạy thật trên Windows amd64 / Go 1.26.11; số `ns/op`, `B/op`, `allocs/op` được ghi ở `docs/BENCHMARKS.md`. Body 64–256 KB vượt 2 ms rõ rệt, body 8 KB sát/vượt 2 ms.
- `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0.
- `go test -count=1 ./...` trong WSL Ubuntu, Go 1.26.11 → PASS tất cả package. `go test -race -count=1 ./...` trong WSL Ubuntu, Go 1.26.11 → PASS tất cả package. Lần chạy cùng lệnh trong sandbox Windows thất bại ở test loopback do Windows trả `connectex ... forbidden by its access permissions`; WSL ngoài sandbox đã xác minh lại xanh.

### Chưa xác minh

- Không có held-out độc lập; chờ corpus v3 do người dùng/reviewer cung cấp.
- Chưa so sánh với Coraza/OWASP CRS; cần mạng (TODO-1 trong `docs/BENCHMARKS.md`). Corpus hoàn toàn tự viết nên số đo không đại diện traffic thực.
- Chưa xác minh GitHub Actions sau push.

### Nợ kỹ thuật

- Latency body lớn hơn ngân sách 2 ms: `BodyText` đọc có giới hạn kích thước nhưng đồng bộ; phase chỉ phát hiện vượt ngân sách sau bước đọc và chọn fail-open/fail-closed. Chưa thể ngắt việc đọc theo deadline.
- `waf_budget_exceeded` được phơi qua Decision/Tag để pipeline quan sát, nhưng hiện chưa có sink audit bất đồng bộ ghi sự kiện này. Không khẳng định “đã log” bền vững; cần nối với logging pipeline theo quy tắc không chặn request.
- Chi tiết trạng thái hiện hành về deadline body, audit sink, coverage và corpus v3 xem mục P4d ở đầu file.

### Lệnh tự chạy lại

```sh
golangci-lint run ./...
go vet ./...
go test -count=1 ./...
go test -race -count=1 ./...
go test ./edge/internal/waf -run '^$' -bench 'BenchmarkWAF(ManagedClean|ManagedEarlyExit|WorstCase)$' -benchtime=10x -benchmem
```

## Kiểm chứng gần nhất — 2026-11-22

### Đã xác minh

- **P4 lượt 2/2:** mở rộng `edge/rulesets/managed.yml` thành 19 luật mẫu, phủ SQLi, XSS, traversal/LFI, RFI, RCE, SSRF (metadata/loopback/private IPv4), XXE, SSTI, deserialization, giao thức (thiếu Host/phương thức lạ/CL+TE/Content-Length trùng), scanner UA, tệp nhạy cảm và marker virtual patching. Mỗi rule có ID riêng, targets, transforms, RE2, severity, paranoia 1–4 và OWASP tag. Loader kiểm tra regex và size, targets/transforms/tags, ID trùng trong file và ID trùng toàn ruleset khi nạp/biên dịch; test xác nhận ruleset nhúng biên dịch.
- Attack corpus tự viết `test/corpus/waf/attacks.tsv`: 20–21 mẫu cho mỗi 13 nhóm; clean corpus `test/corpus/waf/clean.tsv`: 46 mẫu form/JSON/search/path/header/body. `TestManagedCorpusTPRFPR` in TPR/FPR theo nhóm và paranoia; trần FPR cấu hình qua `WAF_FPR_MAX` (mặc định 0), baseline TPR ghi tại `test/corpus/waf/tpr-baseline.json`, có thể tăng trần kiểm tra qua `WAF_TPR_MIN` nhưng không hạ baseline. Đo thật: TPR 100% cho mọi nhóm/paranoia, ngoại trừ marker virtual patch có chủ ý chỉ bật ở P4 (0% ở P1–P3, 100% ở P4); FPR 0/46 tại cả bốn mức. Test né tránh double encoding, case, SQL comments, whitespace, NUL, Unicode và CL+TE đều PASS.
- `go test -count=1 -v ./edge/internal/waf ./edge/rulesets` → PASS; log có bảng TPR/FPR theo từng nhóm và P1–P4. `go test -count=1 ./...` → PASS toàn bộ packages (Go 1.26.11 Windows/amd64, chạy ngoài sandbox để cho phép loopback).
- `golangci-lint run ./...` (golangci-lint v2.15.0) → PASS, `0 issues.` `go vet ./...` → PASS, exit 0.
- `/usr/local/go/bin/go test -race -count=1 ./...` trong WSL/Linux (Go 1.26.11, CGO bật) → PASS toàn bộ packages trên trạng thái source cuối cùng.
- Benchmark 5 lần trên Windows/amd64, Go 1.26.11, Intel Core i5-11400H: `BenchmarkWAFManagedClean` median **25,462 ns/op, 6,831 B/op, 28 allocs/op**; `BenchmarkWAFManagedEarlyExit` median **10,134 ns/op, 7,093 B/op, 38 allocs/op**. Hai benchmark dùng bộ 19 rule và ngân sách 2 ms; chi tiết và bảng TPR/FPR ở `docs/BENCHMARKS.md`.
- **Test loopback** (`TestLoopback...` ở edgecore/listener/proxy) chạy được ngoài sandbox Windows; suite thường chạy trong sandbox bị từ chối bind/connect localhost. Đã chạy full test ngoài sandbox thành công.

- `go.mod` ghim Go 1.26.11 (bản vá mới nhất nhánh 1.26 đã phát hành tại thời điểm này); `go get -u ./...` và `go mod tidy` hoàn tất.
- `go build ./...` → PASS, exit 0 (Go 1.26.11 Windows/amd64).
- `golangci-lint run ./...` (v2.15.0, build bằng Go 1.26.11) → PASS, `0 issues.`
- `go vet ./...` → PASS, exit 0.
- `go test -count=1 ./...` → PASS toàn bộ packages trên Go 1.26.11 Windows/amd64 khi chạy ngoài sandbox để cho phép loopback.
- `/usr/local/go/bin/go test -race -count=1 ./...` → PASS toàn bộ packages trong WSL Linux/amd64 với toolchain Go 1.26.11; race detector bật.
- `govulncheck ./...` (v1.10.0) → PASS, `No vulnerabilities found.`; `govulncheck -show verbose ./...` quét 19 root packages, 7 modules và standard library Go 1.26.11, không thấy vulnerability bị gọi tới.
- Redis integration sau nâng go-redis v9.23.0: `redis-cli ... ping` → `PONG`; `go test -tags=integration -count=1 -v ./edge/internal/ratelimit` trong WSL → PASS, gồm Lua concurrent và outage/fallback/recovery.
- P4 follow-up về lint/security (Go 1.26.11, WSL): `golangci-lint v2.15.0 run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go test -race -count=1 ./...` → PASS toàn bộ; `go test -tags=integration -race -count=5 ./edge/internal/ratelimit` → PASS (`28.195s`); `govulncheck ./...` → `No vulnerabilities found.`
- G710: listener xác thực host bằng router hiện hành, chỉ dùng hostname canonical từ site trong snapshot để dựng absolute Location; host sai trả 421. Test kiểm tra evil.com, userinfo/ký tự lạ, nhiều dấu hai chấm, path/query mã hóa và path `//evil.com` vẫn không đổi authority.
- G706/G705: edge bỏ qua `X-Request-ID` client và tự sinh ID hex; proxy chỉ log ID đã kiểm tra dạng hex với `%q`, error body text/plain không phản chiếu ID, có `nosniff`; test bơm CR/LF xác nhận không tạo dòng/header giả và ID không vào body. Còn đúng một `//nolint:gosec` hẹp ở log: G706 không phân tích sanitizer hex tùy chỉnh; lý do cụ thể đặt tại dòng code, còn `TestProxyErrorDoesNotLogOrReflectUnsafeRequestID` chứng minh chuỗi điều khiển bị thay bằng ID rỗng trước log.
- G115: token bucket lưu tokens unsigned, clamp refill theo khoảng trống của bucket trước cộng, saturate khi đồng hồ tiến qua span tràn số; test `TestTokenBucketCapsExtremeRefillAndClockSpan` dùng refill `MaxUint64`, bucket gần/đầy và đồng hồ MinInt64→MaxInt64. Dọn key limiter giữ shard index unsigned, không còn suppression ép kiểu.
- SA1019: dùng `httputil.ReverseProxy.Rewrite`; Rewrite bỏ mọi `X-Forwarded-*`/`X-Real-IP` client gửi, đặt lại IP/proto/host/request ID, ghi Via edge sau khi kiểm tra loop; thư viện xử lý hop-by-hop headers. Test forwarding headers/hop headers/HostHeader cùng các test WebSocket, SSE và retry GET/HEAD giữ PASS.
- Punycode: digit dùng bảng tra với kiểm tra miền; test phủ 0..35 và -1/36/giá trị lớn.
- Dependency update thực tế: `github.com/redis/go-redis/v9` 9.7.3 → 9.23.0; `github.com/cespare/xxhash/v2` 2.2.0 → 2.3.0; `golang.org/x/sys` 0.21.0 → 0.50.0; bỏ `go-rendezvous` và thêm `go.uber.org/atomic` 1.12.0. Govulncheck verbose xác nhận 7 module được nạp sạch; không có third-party vulnerability cần sửa thêm.
- Các finding lint mới đã được xử lý tại gốc, không tắt/nới rule: `ReverseProxy.Rewrite`, canonical host redirect, ID hex do edge sinh, body lỗi text-only/nosniff, bucket arithmetic unsigned/saturating, và punycode lookup bounds.
- Workflow `lint`, `test-race`, `govulncheck`, `test-integration`, `compose` đều cài Go bằng `actions/setup-go@v5` + `go-version-file: go.mod`; govulncheck là cổng bắt buộc, không có `continue-on-error`. Redis integration và Compose vẫn là job riêng.
- `go test -count=1 ./pkg/wafcore ./edge/internal/access ./edge/internal/ratelimit ./edge/internal/router ./edge/internal/pipeline ./edge/internal/configsync` → PASS.
- `go test -tags=integration -count=1 -v ./edge/internal/ratelimit` → PASS, gồm cả hai test Redis thật; Redis tại `localhost:6379` truy cập được trong lần chạy này.
- Benchmark access/rate limit đã chạy 5 lần. Median và allocs/op được ghi trong `docs/BENCHMARKS.md`.
- `TestSnapshotYAMLRoundTrip` đọc `test/fixtures/snapshot.sample.yaml`, validate, round-trip YAML → JSON → struct và so sánh struct; `TestDSLErrorGolden` có 13 golden case với lỗi chính xác gồm dòng/cột.
- P4 lượt 1: đã thêm custom rules phase theo priority, mode log, expiry, allow/block/challenge/log/rate_limit/tag/skip; body được phát hiện qua token DSL, đọc lazy một lần trong giới hạn entitlement và phát lại đầy đủ cho origin. WAF khung có loader YAML (chỉ 3 luật mẫu sqli/xss/traversal), normalizer decode tối đa 3 vòng/cờ double-encode, HTML entity/NUL/path/lowercase/whitespace/SQL comment, Aho-Corasick tiền lọc rồi RE2, scoring/sensitivity/paranoia/exclusions/budget/fail_mode/early stop.
- P4 benchmark số liệu tại `docs/BENCHMARKS.md` được đo trước nâng toolchain trên Go 1.26.5; không đại diện cho Go 1.26.11.
- Các test `TestLoopback...` chỉ chạy được ngoài sandbox Windows; lần xác minh full suite xanh này đã được chạy ngoài sandbox.

### Chưa xác minh — lệnh tự chạy lại

- **Chưa xác minh:** kết quả GitHub Actions sau khi push thay đổi này. Cấu hình đã ghim Go 1.26.11 chung cho các job.
- **Chưa xác minh:** đối chiếu Coraza/OWASP CRS, cần mạng để tải bộ so sánh (TODO-1 trong `docs/BENCHMARKS.md`).
- Windows có `CGO_ENABLED=0` nên không chạy được race tại host đó; race đã được xác minh trong WSL. Lint chạy trên Windows bằng `golangci-lint run ./...`, test thường bằng `go test -count=1 ./...`; các lệnh tương ứng với target `make lint test`. Chạy CI GitHub sau khi push để xác minh workflow hosted.
- Chạy lại các lệnh xác minh khi có thay đổi tiếp theo: `go build ./...`, `golangci-lint run ./...`, `go vet ./...`, `go test -count=1 ./...`, `/usr/local/go/bin/go test -race -count=1 ./...`, `govulncheck ./...`.

Các mục lịch sử bên dưới ghi phạm vi phase; trạng thái xác minh hiện tại trong mục này là nguồn mới nhất.

## Điều tra CI đỏ và cấu hình mới — 2026-11-22

> Phần này là bản ghi lịch sử trước lỗi govulncheck; các version 1.22.8 / v2.1.6 / v1.1.4 bên dưới đã được thay thế bởi kiểm chứng mới nhất ở đầu tài liệu.

### Workflow tại từng commit đỏ

- `d3b293c` (#1): workflow ghim `golangci-lint-action@v6` cùng golangci-lint `v2.0.2`. Đây là cặp action/linter không tương thích (action v6 không hỗ trợ dòng v2). Không có log của run này trong dữ liệu hiện có, nên không khẳng định nguyên văn thông báo lỗi. Job `test` phụ thuộc lint; `govulncheck` phụ thuộc test. Compose là job độc lập, không có `needs`.
- `94fba84` (#2): workflow ghim action v6 cùng linter `v2.1.6`, trùng cặp phiên bản trong log lỗi người dùng cung cấp. Không có run ID đi kèm log để gán chắc chắn thông báo đó riêng cho #2 hay #3. Nếu lint đỏ, job test và govulncheck bị chặn bởi `needs`; Compose vẫn là job độc lập.
- `3d4fba5` (#3): vẫn ghim action v6 và linter `v2.1.6`, nên cấu hình có cùng nguyên nhân tương thích. Workflow có thêm các bước Compose `config`, `pull`, `up --wait`, nhưng job Compose không phụ thuộc lint và có thể chạy độc lập. Chưa có log để nói nó pass hay fail.

Lấy log còn thiếu cho từng run: `gh run list --commit <commit>`, sau đó `gh run view <run-id> --log-failed`. Không suy đoán lỗi của test-race, govulncheck hoặc Compose khi chưa có log.

### Thay đổi workflow hiện tại

- Lint lúc đó dùng `golangci-lint-action@v8` với linter `v2.1.6`.
- Lint, race test, govulncheck, Compose và integration là các job độc lập. Race test vẫn chạy `go test -race -count=1 ./...`; không bỏ lint, race hay test.
- Govulncheck lúc đó cài CLI `golang.org/x/vuln/cmd/govulncheck@v1.1.4` theo phiên bản cố định; cấu hình hiện tại là v1.10.0.
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
