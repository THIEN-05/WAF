# Quyết định kiến trúc P0

## P7 site/origin/rules/billing — 2026-11-25

- Outbound origin resolution/dial phải đi qua `pkg/netguard`: reject toàn bộ DNS answer set nếu có IP không an toàn và resolve lại ngay trước khi dial numeric IP. Edge tắt `ProxyFromEnvironment`, vì forward proxy có thể tự resolve origin và bypass guard. `203.0.113.0/24` được coi là unicast trong unit tests, không phải production target; test dùng resolver/dialer giả.
- Verification token domain chỉ trả cho người dùng khi tạo; DB chỉ giữ SHA-256. TXT `_waf-verify.<hostname>` mang token gốc; worker hash TXT rồi constant-time compare với digest DB. CNAME proof có dạng `verify.<token>.waf.invalid`. Hostname global uniqueness tiếp tục do unique constraint `domains.hostname` đảm bảo.
- Tạo site lấy advisory transaction lock theo tenant rồi kiểm quota và insert trong cùng transaction để hai request đồng thời không vượt quota.
- Lịch sử quyết định P7: domain activation ghi `config_change_outbox` cùng transaction. P8a làm rõ API chưa được nối NATS và chưa có dispatcher; xem TODO-P8A-OUTBOX-1, quyết định cũ về best-effort đã được thay thế.
- Đợt này chỉ là lát MVP: validator DSL/CSV và FakeProvider/signature verification chưa thay thế rule CRUD/billing lifecycle. Không coi phần §5.4 hoặc §5.6 là đã hoàn tất.
- Danh sách nợ được theo dõi trong `docs/PROGRESS.md`: TODO-P7-SITE-1 (probe cô lập + E2E), TODO-P7-RULES-1 (CRUD/quota/history/ETag/idempotency), TODO-P7-BILLING-1 (Stripe/webhook worker/subscription/invoices), TODO-P7-OUTBOX-1 (dispatcher bền vững), TODO-P7-TEST-1 (integration matrix).

## P8a — role và bằng chứng site — 2026-11-25

- `waf_api` chỉ có quyền INSERT theo cột trên `config_change_outbox`; không được SELECT/UPDATE/DELETE. `waf_worker` có quyền theo cột để đọc/claim/đánh dấu event và INSERT event phát sinh từ worker; RLS tenant `ENABLE` + `FORCE` vẫn là mặc định, nhưng `waf_worker` là BYPASSRLS nên mọi job bắt buộc dùng code path có tenant id/audit. Regression test kiểm các cột/quyền này.
- `domains.verification_token_hash` không mở cho API role. `site_add_domain` SECURITY DEFINER là đường ghi duy nhất của API; nó ràng buộc `app.user_id`, `app.tenant_id`, owner/admin membership, kiểm tra site và ghi audit. Domain token hạn 24h; TXT hash compare hằng thời gian. CNAME proof dùng target dẫn xuất từ SHA-256 dưới zone cấu hình, không hardcode domain placeholder.
- Quota site được kiểm trong cùng transaction sau advisory transaction lock theo tenant; unique index toàn cục trên `domains.hostname` xử lý race giữa tenants. API trả conflict generic để không tiết lộ tenant sở hữu hostname.
- **Chưa chấp nhận exactly-once cho NATS outbox:** không thể đồng thời bảo đảm không mất event và không duplicate khi crash giữa publish/mark với core NATS thuần. Cần JetStream dedupe theo message ID/consumer idempotency hoặc protocol tương đương. Theo dõi TODO-P8A-OUTBOX-1.
- `ProbeOrigin` tự nó không tạo sandbox mạng; production worker phải chạy trong network namespace/egress ACL chặn private/internal control-plane ranges. Theo dõi TODO-P8A-WORKER-1.
- Các bằng chứng runtime Postgres, migration cycle, full race, SQL checker và govulncheck chưa có trong lượt này; xem trạng thái/commands trong `docs/PROGRESS.md`. Không đánh dấu P8a đóng đến khi TODO-P8A-DB-1, WORKER-1 và IDOR-1 được chứng minh; API/dispatcher requirements còn mở theo số TODO tương ứng.

Ngày: 2026-11-20

## Quyết định đã chốt

- Dùng Go 1.22+ với một module gốc `github.com/example/wafplatform`.
- Dùng chung `pkg/wafcore` cho DSL, schema snapshot, schema log và ký/kiểm tra Ed25519.
- Edge dùng `net/http` và `httputil.ReverseProxy` với Transport tùy chỉnh; regex dùng RE2 của Go.
- Control plane dùng chi, pgx/sqlc, goose, PostgreSQL, Redis, NATS, ClickHouse, MinIO và scheduler River hoặc goroutine.
- Xây auth nội bộ với argon2id, JWT EdDSA 15 phút và refresh token xoay vòng.
- Thanh toán dùng Stripe test mode qua `PaymentProvider`, có `FakeProvider` cho test.
- Bí mật đi qua interface `SecretStore`; môi trường dev dùng file/env mã hóa, phương án production AWS để sau.
- Dashboard dùng Next.js, TypeScript, Tailwind, TanStack Query, Recharts và hỗ trợ vi/en.
- Phạm vi chỉ L7; DDoS L3/L4 nằm ngoài sản phẩm.
- Theo hợp đồng CP↔edge mục 2.3: đăng ký edge bằng HTTPS và token một lần; snapshot có version ký Ed25519 được lấy qua long-poll/ETag, có thông báo NATS; kênh khẩn qua NATS; chứng chỉ/bí mật qua mTLS; log theo lô qua NATS hoặc HTTPS; heartbeat qua HTTPS/NATS; dữ liệu tham chiếu nằm trong snapshot hoặc tải riêng có chữ ký.
- Schema snapshot và sự kiện log là một module `pkg/wafcore` dùng chung.

## Mặc định cho các điểm mục 13 chưa chốt

1. Ngôn ngữ CP: Go, dùng chung waf-core với edge.
2. Xác thực: tự xây theo quyết định MVP ở trên; không triển khai Keycloak trong P0.
3. Cổng thanh toán demo: chỉ Stripe test mode; giữ interface để thêm PayOS/VNPay sau.
4. Apex domain: dùng ALIAS/CNAME flattening phía khách; cung cấp A record cố định theo vùng làm phương án dự phòng, chưa cam kết anycast.
5. Vùng CP và SLA: một vùng chính cùng sao lưu; SLA gói demo ghi mục tiêu 99,9%, không quảng cáo mức Enterprise 99,99% trước khi có hạ tầng/đo đạc phù hợp.
6. Analytics demo: ClickHouse; giữ schema/repository có thể đổi sang TimescaleDB nếu chi phí vận hành quá cao.
7. Phạm vi bản đầu: API công khai và back-office tối thiểu trong MVP; export SIEM để sau.
8. DNS tự động: chưa chọn nhà cung cấp; bắt đầu bằng xác minh thủ công và interface adapter DNS.
9. Quyền riêng tư và điều khoản: chưa tự kết luận pháp lý; trước khách thật cần chính sách được chuyên gia rà soát. P0 chỉ ghi nhận đây là yêu cầu triển khai, không thu thập dữ liệu ngoài mức cần thiết.

## Quyết định scaffold P0

- Các server hiện chỉ cung cấp `/healthz`, bind theo biến môi trường riêng và dừng graceful khi nhận SIGINT/SIGTERM.
- Docker Compose dùng image có tag cố định và dữ liệu dev local; thông tin đăng nhập mặc định chỉ phục vụ máy phát triển.
- Thay MinIO trong Compose dev bằng SeaweedFS S3 gateway: tag `4.54` đã có trên Docker Hub và image được ghim cả digest. Tag MinIO `RELEASE.2025-02-07T23-21-09Z` không có manifest; MinIO community không còn cung cấp image ổn định phù hợp cho thiết lập sạch. SeaweedFS được chọn làm S3-compatible local storage, endpoint `localhost:8333`; Compose mặc định không cần đăng nhập registry.
- CI chạy tuần tự lint → test → govulncheck; dependency Go ghim phiên bản trong `go.mod`/`go.sum`.

## Quyết định CI — 2026-11-22

- Bản Go phải luôn là bản vá mới nhất còn được hỗ trợ trong nhánh đang chọn; không giữ bản vá cũ chỉ để khớp máy phát triển. Cập nhật `go.mod` và xác minh lỗ hổng thư viện chuẩn định kỳ.
- Dùng Go **1.26.11** hiện tại trong `go.mod`; tất cả job CI dùng `actions/setup-go` với `go-version-file: go.mod`. Go 1.22.8 của WSL trước đây không còn là phiên bản chuẩn do các cảnh báo bảo mật thư viện chuẩn.
- Ghim golangci-lint action ở `golangci/golangci-lint-action@v8` và linter ở `v2.15.0` (bản phát hành tương thích Go 1.26); action v6 trong workflows cũ không hỗ trợ golangci-lint v2.
- Ghim govulncheck CLI ở `golang.org/x/vuln/cmd/govulncheck@v1.10.0`; workflow cài CLI theo tag cố định thay vì dùng `@latest`.
- `govulncheck ./...` là cổng CI bắt buộc. Không tắt job, không dùng `continue-on-error`, và không chấp nhận lỗ hổng bị gọi tới như kết quả xanh.
- CI tách lint, `go test -race -count=1 ./...`, govulncheck, Compose và Redis integration thành job độc lập. Compose/mạng không điều kiện tiên quyết cho lint, test hoặc vulnerability scan.

## Quyết định P1 — waf-core

- Snapshot và log dùng `schema_version: 1`; snapshot phiên bản cấu hình riêng dùng uint64 `version`.
- `plan` và `entitlements` là dữ liệu riêng: plan là nhãn gói, entitlements là quota hiệu lực mà CP đóng vào snapshot.
- Snapshot chỉ giữ ID tham chiếu secret (`challenge_hmac_key_id`, `origin_credential_ids`, `additional`), không chứa secret dạng rõ; truyền bí mật thực tế thuộc kênh mTLS theo hợp đồng 2.3.
- Signed envelope P1 là JSON có `kid`, checksum SHA-256 trên bytes gzip payload, chữ ký Ed25519 trên domain-separated `kid + checksum`, payload gzip JSON base64 theo encoding `[]byte` chuẩn JSON.
- Hành động là trường typed riêng của rule; biểu thức DSL chỉ trả bool. Các action hiện hỗ trợ: allow, block, challenge, log, rate_limit, tag, skip.
- CIDR trong DSL được viết literal không nháy theo ví dụ tài liệu. Giá trị regex phải là literal string và compile bằng regexp RE2 của Go.
- Giới hạn mặc định DSL: biểu thức 4 KiB, 512 AST nodes, regex 256 bytes; caller có thể truyền giới hạn thấp/cao hơn theo entitlement.

## Quyết định P2 — edge core

- Metrics được đưa sau interface `pipeline.Metrics`; exporter text format ban đầu đã được thay ở P12 bằng `prometheus/client_golang`. Label metric toàn cục có miền giá trị hữu hạn và không chứa `site_id`.
- PROXY protocol hiện chỉ hỗ trợ v1 và chỉ nhận từ CIDR tin cậy. TODO: thêm v2 để tương thích NLB.
- P8 đã thay `Fingerprinter` stub bằng capture ClientHello có giới hạn 16 KiB và JA3/JA4; xem phần P8 ở cuối file. Capture hiện chỉ tính fingerprint cho ClientHello nằm trọn trong một TLS record; hello phân mảnh qua nhiều TLS records để trống an toàn.
- Snapshot production luôn phải qua Ed25519 verify theo `kid`; unsigned local JSON/YAML chỉ được bật ngoài production với `EDGE_DEV_UNSIGNED=1`. Keyring nhận nhiều mục qua env hoặc file.
- DNS origin được kiểm tra khi nạp cấu hình và resolve/recheck ngay trong dial để chống DNS rebinding. Chuẩn hóa domain hiện hỗ trợ lowercase, port/trailing dot và punycode cơ bản; TODO: UTS #46 đầy đủ nếu yêu cầu domain quốc tế hóa nâng cao.
- Certificate mặc định tự ký chỉ để khởi tạo listener và hoàn tất TLS handshake; router vẫn từ chối Host không khớp SNI. Chứng chỉ production được nạp từ file; phân phối certificate qua kênh mTLS CP↔edge còn chờ phần tích hợp control plane.

## Quyết định P4e — WAF scan scope, truncation và read deadline — 2026-11-24

- P4e thay các trần scan P4d. Thứ tự giữ nguyên: URI path → query → header chọn lọc → cookie → body. Trần body là Free 8 KiB, Pro 64 KiB, Business 128 KiB (tối đa 256 KiB khi entitlement cho phép), Enterprise 256 KiB; `BodyLimitKB`/`MaxBodyBytes` chỉ được hạ trần theo cấu hình hiệu lực. Query parse tối đa 256 KiB / 200 tham số; target tối đa 256 KiB; tổng byte xử lý mặc định tối đa 1 MiB.
- Aho-Corasick chạy trên toàn bộ target trong giới hạn gói. Body được normalize theo block 4 KiB với vùng chồng 512 byte; regex RE2 chỉ chạy trên cửa sổ tối đa 512 byte quanh vị trí keyword. Tối đa 128 cửa sổ/request; khi vượt giới hạn giữ cả 64 cửa sổ đầu và 64 cửa sổ cuối, gắn `waf_scan_truncated` và dùng fail mode. Cắt target/query/header/cookie cũng giữ mẫu đầu+đuôi và không được xem là sạch.
- Nếu body vượt trần gói, edge chỉ buffer `cap+1` byte, giữ lại prefix hữu hạn và để phần dư tiếp tục stream tới origin; phần vượt trần không được đọc hết chỉ để WAF quét. Gắn `waf_body_truncated`, cộng mặc định 3 điểm (`TruncatedBodyScore` có thể cấu hình); phần chưa quét không được coi là sạch và áp fail mode. Điểm 3 chạm sensitivity high (3), nhưng chưa chạm medium (5) hoặc low (10); fail mode có hiệu lực bất kể monitor mode để dữ liệu thiếu không âm thầm qua.
- (Tại thời điểm P4e) Đọc request body có deadline socket mặc định 1 giây; P4f tách lỗi body read/timeout khỏi cầu chì scan: timeout/lỗi đọc gắn `waf_body_truncated`, và timeout gắn `waf_body_read_timeout`, không gắn `waf_budget_exceeded`.
- `fail_mode=open` mặc định cho Free có rủi ro request với body vượt cap/timeout được forward khi không match rule đã quét; audit event vẫn ghi nhận phần WAF không quan sát được. Gói trả phí mặc định `closed` để tránh bypass do body lớn/chậm; có thể gây từ chối upload hợp lệ của client chậm. `site.fail_mode` tường minh luôn được tôn trọng.
- Audit enqueue không chặn, queue bounded và phát count `waf_budget_exceeded`, `waf_body_truncated`, `waf_body_read_timeout`; writer hiện tại vẫn là in-memory. **TODO-2**: thay bằng telemetry bền vững ở P6a.
- Corpus clean body lớn: test tự sinh 30 mẫu hợp lệ (JSON/form/text/multipart) cho mỗi paranoia; FPR đo riêng từng paranoia với ngưỡng 0%. Corpus tự viết chỉ là regression, không phải held-out độc lập.
- Lệnh `sh scripts/measure-waf-corpus.sh <dir>` chỉ nạp `attacks.tsv`/`clean.tsv` ở thư mục người dùng đưa, tải luật project như thường và in TPR theo nhóm; không sửa luật hay commit corpus ngoài.

## Quyết định P4f — ngân sách công việc và suy giảm quá tải WAF — 2026-11-24 (thiết kế trước P4f-fix)

- Ngân sách 2 ms theo giờ tường P4d/P4e đã bị scheduler contention tính nhầm thành lỗi WAF (benchmark trước: p50 2,09 ms / p99 22,05 ms / 250/250 `waf_budget_exceeded`). Ngân sách thường ngày giờ là work cap xác định theo gói: Free 128 KiB, 256 normalize block steps, 128 regex windows; Pro 256 KiB/512/192; Business 384 KiB/768/256; Enterprise 512 KiB/1.024/384. Hết cap là truncated theo fail-mode, không gắn `waf_budget_exceeded`.
- `budget_ms` nay là cầu chì treo thật, mặc định 100 ms, cấu hình 1–5.000 ms; khi WAF in-flight vượt GOMAXPROCS, ngưỡng cầu chì tăng theo backlog ước lượng (tối đa 5 giây) để không tính thời gian chờ scheduler là treo; chỉ cầu chì đã hiệu chỉnh đặt `waf_budget_exceeded`. Lỗi đọc body/timeout vẫn có `waf_body_read_timeout` + truncation và xử lý fail-mode theo hợp đồng P4e.
- Quá tải: mức 1 bỏ paranoia >1 khi backlog ước lượng (in-flight − GOMAXPROCS) >0 hoặc EWMA pha ≥12 ms; mức 2 giảm một nửa các work caps khi backlog ≥GOMAXPROCS hoặc EWMA ≥30 ms; mức 3 áp fail-mode chỉ khi tối thiểu 32 mẫu trong cửa sổ 64 request gần nhất có fuse ratio ≥25% và backlog hiện tại đã thoát ngưỡng. Các tier được log khi chuyển và xuất counter/tag audit. Backlog là proxy vì WAF synchronous không có queue riêng.
- Buffer body vẫn chỉ prefix theo cap và stream phần dư; không có tail scan thật. Candidate windows đầu/cuối nằm trong phần prefix đã đọc. Free fail-open có thể bị padding vượt cap để né phần payload ở đuôi; giảm thiểu bằng anomaly +3 (mặc định), cap Content-Length theo content type và rate-limit chặt hơn upload/body lớn. Gói trả phí nên chọn closed/challenge.
- Tải cao suy giảm theo thứ tự “paranoia cao → phạm vi → fail-mode”; fail-mode cuối vẫn có thể chặn hợp lệ khi cầu chì liên tục, nhưng không chuyển chỉ vì concurrency tăng.

## P4f-fix — cầu chì không từ chối request sạch theo scheduler — 2026-11-24

- Bằng chứng kích hoạt sửa: CI log `level=1 active=2 estimated_runnable_queue=0 ewma_ns=28915914 fuse_ratio=0.016` đi cùng `clean fail-closed requests rejected=1/250`. `budgetFailure` trước đây áp `fail_mode=closed` ngay khi một request vượt fuse wall-clock; level 3 cũng từng đổi fail-mode chỉ từ lịch sử fuse. Do đó một request sạch bị scheduler trì hoãn vẫn có thể bị từ chối dù không vượt work cap.
- Trước khi áp cầu chì, edge hoàn tất các target ưu tiên theo thứ tự URI/path → query → User-Agent/Referer/X-Forwarded-For → cookie → protocol; body nằm sau các target này. Cầu chì có thể dừng body/target còn lại, nhưng không được cắt lượt quét target ưu tiên. Work caps xác định áp dụng xuyên suốt, kể cả trên target ưu tiên.
- Work budget xác định (byte, normalize steps, regex windows) quyết định `waf_work_exhausted` và fail-mode. Cầu chì chỉ là watchdog thô, tối thiểu/mặc định 250 ms, cấu hình hiệu lực tối đa 5 giây và tự tăng theo backlog runnable ước lượng + EWMA, tối đa 10 giây. Fuse giữ điểm cũ, cộng thêm một điểm vì phần scan chưa hoàn tất, và gắn `waf_budget_exceeded`, `waf_scan_truncated`, `waf_degraded_fuse`. Nếu điểm chạm ngưỡng, áp mode (block/challenge/monitor); dưới ngưỡng không áp fail-mode theo thời gian, kể cả fail-closed, để scheduler delay không từ chối request sạch.
- Fail-mode cụ thể: (a) fuse wall-clock dưới ngưỡng: open và closed đều tiếp tục/allow có tag + score; monitor ghi log-only; (b) fuse cùng điểm tích lũy chạm ngưỡng: block/challenge theo mode WAF, bất kể fail-mode; (c) cap công việc xác định hoặc scan input bị cắt: fail-open cho qua có tag `waf_scan_truncated`/`waf_work_exhausted`, fail-closed block; monitor vẫn thể hiện `log-only` với input truncation không phải body, còn body truncation theo fail-mode; (d) body read timeout/lỗi tiếp tục theo chính sách timeout P4e.
- Test fake clock cho payload path/query/header/cookie xác nhận điểm được giữ khi fuse tripped sau khi các target ưu tiên hoàn tất; phần body chưa đọc có scan-truncated tag/score. Test work-cap với 200 query params, keyword Aho-Corasick lặp nhiều lần và JSON lồng sâu: deterministic cap fail-closed block, fail-open allow có tag, không gắn fuse.
- Fuse ratio quá khứ không còn tự kích hoạt fail-mode. Tier 1 bỏ paranoia cao, tier 2+ giảm phạm vi; cap công việc xác định vẫn là giới hạn cuối cùng. Đây ưu tiên không từ chối nhầm do lịch CPU, đổi lại request chưa quét hết dưới mức ngưỡng có thể qua theo fail-open/fail-closed nếu chưa vượt work cap. Dấu `waf_scan_truncated`/điểm fuse dùng cho telemetry/alert.
- Wall-clock stress test được chuyển sang build tag `perf`, chạy riêng trong job bắt buộc không `-race`; logic fuse/work caps và ưu tiên target chạy dưới `-race` bằng fake clock/fake reader/fake regex. Lý do: race detector làm chậm xử lý và không đo độ trễ phục vụ. Job perf chạy 30 lần, GOMAXPROCS 1/2/4/N, 50/200 goroutine và case 1P/200 goroutine có CPU background; tính đúng bắt buộc 0 clean reject, 100% payload trong phạm vi bị chặn, 0 fuse trip ở mọi lượt.
- Số đo Linux/WSL + `taskset` do người dùng cung cấp: GOMAXPROCS 1/2/4 × 50/200 goroutine, 30 lượt, clean reject 0, payload tấn công trong phạm vi bị bắt 100%, fuse 0; p50 khoảng 135 µs, p99 tổng 0,16–23 ms. Tải nền một lõi: 30 lượt, người dùng báo 0/800 clean reject. Đây là xác minh ngoài workspace, được ghi nguồn rõ trong BENCHMARKS.
- Log đổi tier dùng throttle toàn tiến trình tối đa một dòng mỗi 3 giây; mỗi dòng gồm tổng thay đổi, còn counter/accessor giữ số liệu chi tiết.

## Quyết định P4f-fix — perf CI tách tính đúng khỏi scheduler latency — 2026-11-25

- Log GitHub runner 4 CPU cho `GOMAXPROCS=4/workers=200` dao động: pass khoảng 38–48 ms, ba p99 fail 69.88–73.07 ms; cùng các lượt đỏ vẫn clean reject 0/800, attacks 200/200, fuse 0/1000. Nguyên nhân là cổng wall-clock 69 ms áp lên workload quá tải, không phải lỗi tính đúng. Bỏ absolute wall-p99 failure cho mọi cell `goroutines > runtime.NumCPU()`.
- Mỗi `Phase.Handle` được đo bằng thread CPU time trên Linux (`getrusage(RUSAGE_THREAD)` với goroutine ghim vào OS thread); thời gian này không tính thời gian thread bị scheduler gác. Đo serial scan p99 trên cùng runner/GOMAXPROCS mỗi lần chạy; median loaded scan CPU p99 qua 30 lượt phải ≤10× median serial p99. Ô không quá tải dùng median request wall p99 ≤5× serial wall p99. Overload wall p99 chỉ ghi nhận và cảnh báo >2× baseline cùng runner; không fail.
- Tính đúng vẫn fail ngay ở bất kỳ lượt nào bị clean reject, bỏ lọt payload trong phạm vi hoặc fuse trip; không retry, skip hay nới assertion. Latency dùng median qua đủ 30 repetitions để một outlier wall-clock không làm đỏ job. Summary/artifact ghi mỗi cell, runner, OS, nproc, CPU count, GOMAXPROCS, goroutine, p50/p99 wall/CPU, correctness counters; upload artifact bằng `if: always()`.
- Baseline GitHub 4 CPU được cung cấp: GOMAXPROCS=2/200 p99 khoảng 30 ms; GOMAXPROCS=4/200 pass p99 khoảng 38–48 ms (dùng 48 ms làm passing maximum), cảnh báo ở trên 2×. CPU-time baseline được đo tự động trên chính runner để tránh suy ra từ wall-clock.
- `actions/checkout@v7`, `actions/setup-go@v6`, `actions/upload-artifact@v6` dùng Node 24; GitHub-hosted runner `ubuntu-latest` đáp ứng yêu cầu runner hiện hành.

## Audit `//nolint` trong code không-test (10 vị trí)

- `edge/cmd/edge/main.go:359` — `gosec` G304: file token ACME được đọc từ đường dẫn operator cấu hình; không nhận path từ HTTP request.
- `edge/cmd/edge/main.go:408,435` — `gosec` G304: snapshot được đọc từ path operator cấu hình lúc khởi động/đồng bộ; path được `filepath.Clean`, không lấy từ tenant/request.
- `edge/internal/configsync/holder.go:42,44,114` — `gosec` G304: active/last-good snapshot path là filesystem state do operator cấp, không có input request.
- `edge/internal/configsync/holder.go:79` — `gosec` G304: keyring file là path operator cấu hình; nội dung verify theo keyring schema trước khi dùng.
- `edge/internal/proxy/proxy.go:263` — `gosec` G706: request ID đã validate hex và log bằng `%q`; test proxy xác nhận RequestID từ client không được phản chiếu.
- `edge/internal/listener/fingerprint.go:4,277` — `gosec` G401: JA3 yêu cầu MD5 tương thích giao thức; digest chỉ dùng fingerprint bot, không dùng làm MAC/chữ ký/secret; test vector ClientHello xác nhận digest.

## Quyết định P4d — WAF budget và fail mode — 2026-11-23 (đã superseded bởi P4e)

- Lịch sử P4d dùng 4 KiB/request, 2 KiB/target, 1 KiB body prefix và query 8 KiB/64 tham số. P4e đã bỏ các trần này vì tạo điểm mù bypass; xem chính sách scope hiện hành ở mục P4e.
- Body được buffer tối đa theo hai trần: entitlement/site và WAF prefix; phần đã đọc được phát lại trước phần body chưa đọc để origin nhận stream đầy đủ. Nếu body bị cắt, không quét được hoặc lỗi khi đọc, gắn `waf_body_truncated` và cộng `truncated_body_score` (mặc định 3; 0 hoặc bỏ trống dùng mặc định, cấu hình 1–5), không xem request là sạch.
- Deadline 2 ms được kiểm tra giữa các mục tiêu, các bước normalize và nhóm luật. Khi vượt trần, giữ điểm đã cộng, gắn `waf_budget_exceeded` và áp fail mode. Việc đọc một `Request.Body` đang bị client giữ mở có thể chặn trong lệnh Read; giới hạn số byte không tự tạo deadline cho socket. Cần giới hạn đọc body ở listener/transport trước khi tuyên bố hard wall-clock bound.
- `fail_open` khi vượt ngân sách có rủi ro bỏ qua rule chưa kịp chạy; đó là lựa chọn mặc định cho Free để tránh từ chối nhầm, không phải bảo đảm WAF. Gói trả phí nên dùng `fail_mode=closed`; WAF mode `challenge` có thể dùng cho rule match bình thường, nhưng budget timeout vẫn áp dụng `fail_mode`. Cấu hình `site.fail_mode` tường minh luôn được tôn trọng.
- Audit WAF đi qua queue bounded, enqueue không chặn request; queue đầy thì bỏ sự kiện và tăng counter. Hiện writer mặc định là in-memory để quan sát/test, không bền vững qua restart. TODO-2: P6a thay adapter này bằng telemetry bền vững và xác minh giao nhận/dropped metrics.
- Corpus v2 đã bị xem khi tinh chỉnh nên được xem là dev, không phải held-out. Không dùng nó để chốt chất lượng; benchmark TPR/FPR trên thư mục corpus bên ngoài chỉ đánh giá file `attacks.tsv`/`clean.tsv` do người cung cấp, không nạp rules từ thư mục đó.

## Quyết định P8 — bot management và bí mật challenge — 2026-11-23

- Snapshot chỉ mang `challenge_hmac_key_id`; giá trị khóa HMAC thực tế không được đặt rõ trong snapshot. Đây là hợp đồng CP↔edge ở `docs/control-plane.md` §2.3 (bí mật truyền qua mTLS) và quy tắc snapshot ở §5.8. Edge nhận keyring qua interface `bot.KeyRing`; snapshot định danh khóa dùng cho challenge của site. Bản hiện tại có adapter env operator-provisioned (`EDGE_CHALLENGE_HMAC_KEYS`) để chạy/test; tích hợp nhận và xoay keyring tự động qua mTLS chưa có, là TODO P8-3. Khi xoay khóa, keyring phải giữ key ID cũ tối thiểu 30 phút sau khi ngừng ký cookie mới.
- Free không có `bot_js_challenge`; khả năng được thể hiện bằng entitlement, còn `bot.mode` là policy. Challenge PoW mặc định 18 bit, cấu hình 1–24 bit; proof ticket sống 5 phút và cookie HMAC sống 30 phút, ràng buộc site, hash User-Agent, IPv4 /24 hoặc IPv6 /64.
- PoW ticket được dùng một lần trong cache replay có giới hạn riêng từng edge. Đây không phải replay store phân tán; credential cookie vẫn dùng được ở edge khác trong TTL nhờ cùng keyring. TODO P8-1: chuyển ticket replay state sang telemetry/cache dùng chung nếu threat model yêu cầu chống replay xuyên edge.
- Bot scoring chỉ nhận header có trong `net/http.Request`; Go không giữ thứ tự byte của header sau parse nên tín hiệu thứ tự header chưa được chấm. TODO P8-2: nếu cần, bổ sung parser HTTP có lưu thứ tự mà vẫn giữ an toàn request smuggling.
- DNS xác minh bot có cache TTL/cap và timeout 300 ms; operator phải cấp suffix/dải IP chính thức cho từng nhà cung cấp. Không tin User-Agent đơn lẻ.
- JS challenge chỉ làm tăng chi phí cho bot đơn giản; nó không ngăn bot nâng cao dùng trình duyệt thật. Turnstile hiện chỉ có interface/stub từ chối mặc định; chưa có API secret hoặc xác minh dịch vụ thật.

## Quyết định P5a — hardening fingerprint, bot state và challenge — 2026-11-24

- ClientHello capture giữ tối đa 64 KiB dữ liệu record trên mỗi kết nối để tính lại hello tối đa 16 KiB; có thể ghép hello qua tối đa 16 TLS handshake record để chặn chi phí phân tích tăng bậc hai khi bị phân mảnh thành nhiều record rất nhỏ. Peek có deadline cố định 3 giây từ Accept, được xóa khi ClientHello hoàn chỉnh (kể cả hello đã xác định vượt cap). Hết hạn/malformed/không hỗ trợ hoặc vượt cap không tạo fingerprint. Thời hạn peek cài qua `listener.Config.ClientHelloTimeout`.
- Vector độc lập nằm ở `testdata/fingerprints/`: hai raw record lấy từ pcap FoxIO JA4 commit `4ab8e3f18f4b27e0b896c4ec2c251e20506eb87e`, file hash kiểm tra lần lượt `e05937fe5f3659f1b94b46305e419b878ba309ebcba8308750acaac704112906` và `8c00fd3e6c370b39dac61ad3a15c693088f74f3dbc836ee4e8f57105b1e84a91`. Expected JA3/JA4 được đối chiếu với output community repo commit `797a8b074e135f659da1ee3193b5a4cc111dfc26`; vector TLS 1.2 còn đối chiếu JA3 bằng script Salesforce commit `502cc6395811c54743b0561419d61900a6df3ff7` với dpkt v1.9.1 (`6cd0909d613a66033ecdefaca6cc07cfa7d46d6b`). Links và pin đầy đủ nằm trong comment từng test.
- Verified-bot DNS không chạy trên request path khi cache miss: 8 worker mặc định, queue 128, timeout 300 ms, trần 100 lookup/giây, cache dương/âm 10 phút tối đa 10.000 địa chỉ. `NewVerifiedResolverWithLimits` cấu hình timeout, concurrency, tốc độ và capacity. Cache miss/pending luôn chưa xác minh; reverse+suffix+forward-confirm có kết quả mới áp dụng cho request tiếp theo.
- Hành vi bot giữ state ở 32 shard, cap toàn cục mặc định 100.000 key, TTL 10 phút. Key mới khi cap đầy vẫn được đánh giá theo tín hiệu UA/header/IP không trạng thái, nhưng không lưu bộ đếm hành vi; state hết hạn được xóa khi key được chạm lại hoặc khi shard dọn để nhận key mới.
- Challenge verify mặc định 20 POST/phút/IP, tối đa 10.000 IP state, body 8 KiB và deadline đọc/xử lý 1 giây. Navigation GET/HEAD có `Accept: text/html` mới nhận HTML; API/XHR/JSON nhận lỗi JSON kèm request ID. Cookie `__Host-waf_verified` dùng Secure, HttpOnly, SameSite=Lax, Path `/`, không Domain; keyring thiếu khi entitlement bật làm startup lỗi mà không in secret.

## Quyết định Gate G — tương thích snapshot và PROXY protocol

- Decoder YAML v3 và `encoding/json` giữ hành vi bỏ qua field chưa biết; trường tùy chọn bị thiếu trong snapshot cũ giữ zero value, mặc định tắt tính năng. Điều này giữ tương thích mở rộng ở schema version 1; contract test khóa hành vi này.
- Gate G chỉ harden PROXY protocol v1 hiện có: header tối đa 108 byte, CRLF và địa chỉ/port đúng định dạng; lỗi header đóng kết nối. Nguồn không thuộc CIDR tin cậy không được parse header. Chưa triển khai PROXY protocol v2 vì repo chưa có nhu cầu NLB cụ thể và không thêm parser/protocol mới vào đợt đóng nợ này; ghi **TODO-G-1**.

## Gate G-2 — audit suppression và hostname — 2026-11-24

Các `//nolint` còn lại được giữ vì có ranh giới tin cậy rõ ràng và test cụ thể; không dùng suppression mới để né lỗi. Audit từng vị trí:

| Vị trí | Linter | Lý do giữ | Test chứng minh |
|---|---|---|---|
| `edge/cmd/edge/main.go:207` | G304 | File ACME HTTP-01 chỉ được chọn bởi operator qua cấu hình khởi động; request không cung cấp path. | `TestLoadChallengesReadsConfiguredOperatorFile` |
| `edge/cmd/edge/main.go:237` | G304 | Snapshot YAML đọc từ `EDGE_SNAPSHOT_FILE`, chỉ trong nhánh development có opt-in unsigned. | `TestLoadSampleYAMLSnapshotNeedsExplicitDevelopmentFlag` |
| `edge/cmd/edge/main.go:264` | G304 | Fallback unsigned JSON cũng chỉ dùng path `EDGE_SNAPSHOT_FILE` trong development và cần `EDGE_DEV_UNSIGNED=1`. | `TestLoadSnapshotUnsignedJSONDevelopmentFallbackReadsConfiguredFile` |
| `edge/internal/configsync/holder.go:42` | G304 | `LoadLocal` nhận snapshot path cấu hình operator, không nhận dữ liệu request. | `TestLoadLocalUsesOperatorPathAndLastKnownGood` |
| `edge/internal/configsync/holder.go:44` | G304 | Last-known-good path do operator truyền vào Holder khi khởi tạo; fallback chỉ đọc file đó. | `TestLoadLocalUsesOperatorPathAndLastKnownGood` |
| `edge/internal/configsync/holder.go:79` | G304 | File keyring chỉ được trỏ qua `EDGE_PUBLIC_KEYS_FILE`; keyring được parse/kiểm tra trước dùng. | `TestLoadPublicKeysFromEnvAndFile` |
| `edge/internal/configsync/holder.go:114` | G304 | Snapshot ký được đọc từ file operator cấu hình rồi xác minh Ed25519 trước khi trả. | `TestLoadSignedFileReadsConfiguredOperatorPath` |
| `edge/internal/listener/fingerprint.go:4` | G401 | JA3 quy định MD5 làm fingerprint tương thích; digest không dùng cho xác thực hay bảo vệ tính toàn vẹn. | `TestFingerprintIndependentFoxIOChromeCapture`, `TestFingerprintIndependentFoxIOTLS12ALPNCapture` |
| `edge/internal/listener/fingerprint.go:277` | G401 | Cùng lý do JA3; chỉ băm chuỗi fingerprint theo định dạng giao thức. | `TestFingerprintIndependentFoxIOChromeCapture`, `TestFingerprintIndependentFoxIOTLS12ALPNCapture` |
| `edge/internal/proxy/proxy.go:257` | G706 | ID correlation được kiểm tra hex trước log, format `%q`; lỗi transport chỉ log kiểu lỗi, không nội dung attacker-controlled. | `TestProxyErrorDoesNotLogOrReflectUnsafeRequestID` |

Vị trí cũ `edge/internal/proxy/proxy.go` G115 đã được gỡ: counter chuyển sang signed modular arithmetic có chuẩn hóa số âm; `TestWeightedOriginSelectionCounterNearInt64Maximum` kiểm tra wraparound. Host authority chỉ nhận port 1–65535, hostname/label theo trần DNS và IP IPv6 được biểu diễn dạng bracket để chuẩn hóa lặp lại ổn định. `FuzzNormalizeHost` kiểm tra các seed authority lỗi, quan hệ với `url.Parse`/`net.SplitHostPort` và tính idempotent; `TestHostAuthorityConsistentAcrossRedirectRoutingAndSNI` khóa kết quả listener redirect, router và SNI.

## P6a — tích hợp edge với control plane (MVP interface) — 2026-11-24

- `CPClient` là ranh giới API để dùng server giả; `HTTPClient` hiện triển khai HTTPS bootstrap `POST /v1/edges/register` với one-time bearer token + CSR, sau đó `/v1/snapshot?since=` (ETag/304), heartbeat, renewal và secrets chỉ qua TLS client certificate. Redirect HTTP bị tắt; endpoint phải là HTTPS. Contract test với CP/NATS thật thuộc P9.
- Client ECDSA key/CSR và certificate identity chỉ ở RAM. Certificate chain phải khớp private key, verify với CA từ registration và có `clientAuth`; renewal tạo key/CSR mới trước hạn, cập nhật client mTLS và đóng idle connections dùng cert cũ. NATS được biểu diễn bằng `Notifier`/`EmergencyNotifier`; không thêm NATS SDK ở edge trong lượt interface này.
- Snapshot signed được verify (nhiều `kid`), schema validate bởi `wafcore`, chuyển qua `SnapshotInstaller` để compile + atomic runtime swap rồi mới persist LKG bằng temp file, fsync và rename. Lỗi signature/compile giữ runtime cũ; LKG lỗi được báo riêng vì runtime đã swap. `Status`, `SnapshotStale`, `/metrics` và heartbeat expose version/age/error; CP/NATS outage không xóa snapshot đang chạy, long-poll vẫn chạy khi notifier lỗi.
- CP secrets và cert website chỉ nằm trong `MemorySecrets`; secret entry tối đa 64 KiB, bundle 4 MiB, cert 10.000 entries và tối đa 16 MiB DER chain. `CertificateStore` cài cert theo SNI, ACME challenge có store atomic bounded 10.000 entry. Kênh khẩn có command Ed25519 domain-separated signature, expiry tối đa 5 phút, nonce replay cache RAM bounded 10.000 và dispatcher chỉ cho 5 action đã liệt kê.
- Startup self-test tạo request GET benign, resolve một site active và chạy toàn bộ phase trong pipeline; `/readyz` chỉ mở sau self-test. Đây chưa gọi origin/ReverseProxy nên không xác nhận end-to-end origin.
- **TODO-P6a-1:** private key identity hiện chỉ RAM; restart sau khi token dùng một lần cần cơ chế lưu/khôi phục identity mã hóa hoặc bootstrap identity khác. Chưa ghi private key dạng rõ ra đĩa.
- **TODO-P6a-2:** adapter NATS thật (mTLS, reconnect, config.updated và signed emergency subject) chưa được nối do không có CP/NATS server contract chạy ở lượt này; interface/fake test có sẵn, contract test P9.
- **TODO-P6a-3:** emergency actions còn cần wiring sang ban table, cache purge, Under Attack, ACME store và process drain; verifier/dispatcher không tự thay đổi runtime nếu không có handler.
- **TODO-P6a-4:** heartbeat collector hiện cho phép inject metrics và gửi snapshot version/age/error/cert expiry/log-drop field; app hiện chỉ điền RAM usage, chưa có CPU/RPS/error rate/p99/log_dropped collector thực.
- **TODO-P6a-5:** self-test mới chạy in-process phases; cần test origin tổng hợp qua ReverseProxy/TLS trước khi gọi là end-to-end startup validation.
- **TODO-P6a-6:** chaos matrix full edge chưa xác minh trong WSL: CP/NATS outage, Redis outage/recovery thật, đồng hồ tiến/lùi và reload khi request đang mở. Các fake tests và test loopback từng phần không thay thế matrix tích hợp.
- **TODO-G-1** còn mở: PROXY protocol v2.
- Khi WAF/rules đọc body, `gzip` được giải nén chỉ trong scan cap của gói và giới hạn expansion tối đa 20× số byte nén (với sàn 1 KiB để đọc header nhỏ); phần vượt giới hạn đánh dấu truncated, không coi là sạch. Encoding không hỗ trợ cũng đánh dấu truncated. Origin vẫn nhận byte nén gốc và framing HTTP gốc.

## Quyết định P3 — access và rate limiting

- Access IP dùng binary radix trie bất biến sau khi dựng, tách IPv4/IPv6. Thứ tự là allow IP → ban tạm/block IP → country/ASN → global blocklist → hook Under Attack. Allow-list thắng ban để giữ đường khôi phục quản trị.
- Entitlement access lấy theo `site.plan`: Free cho IP/CIDR, Pro thêm country, Business/Enterprise thêm ASN. Cấu hình vượt gói bị fail-closed và trả `RuleID=access_config`.
- Geo/ASN dùng `maxminddb-golang` với `Reader` memory-map; đường dẫn nhận từ `EDGE_GEOIP_COUNTRY_MMDB`/`EDGE_GEOIP_ASN_MMDB`, file dữ liệu do operator cung cấp. Kết quả được cache trong `RequestCtx`; resolver lỗi hoặc không có database mặc định fail-open riêng phần Geo/ASN, các lớp IP/global vẫn chạy.
- Global blocklist hiện nạp CIDR qua `EDGE_GLOBAL_BLOCKLIST_CIDRS` làm adapter khởi đầu; danh sách chuẩn có chữ ký trong snapshot/ConfigSync và feed từ CP là TODO. Under Attack đang là interface stub tắt mặc định.
- Rate limit mặc định `token_bucket`, capacity đầy ở request đầu, dùng micro-token và CAS trên atomic pointer; có thể chọn `sliding_window` bằng trường `algorithm`. Key được SHA-256 trước khi lưu; bảng shard có trần toàn cục 100.000 key mặc định, áp dụng thêm `entitlements.max_counter_keys` theo site, TTL hai giờ mặc định và dọn dần theo batch.
- Redis là lớp phân tán eventual: local limiter luôn quyết định không chờ mạng; counter được xếp hàng bounded và chạy Lua `INCR`/`PEXPIRE` theo batch. Kết quả Redis được cache để các request tiếp theo chặn khi ngưỡng toàn cục đã vượt; Redis/queue lỗi thì bỏ qua cache Redis, quay về local. Batch queue đầy có thể mất đồng bộ, không chặn request.
- Key hỗ trợ: `ip`, `ip+path`, `header:<name>`, `cookie:<name>`, `ja3`, `site`. Action `block`/`throttle` trả 429 + Retry-After; `challenge` trả challenge; `ban_s` thêm IP vào ban table TTL. `rule_id` có trong Decision của RequestCtx và log rate-limit.

## P12 — logging và telemetry — 2026-11-24

- `pipeline.Metrics` vẫn là interface; adapter production dùng `prometheus/client_golang` với registry riêng. Label phase, nhóm chặn, method và status class được whitelist/chuẩn hóa; không có tenant/site/path/host/request ID/rule ID làm label toàn cục. Có histogram latency theo phase, request/block/rate-limit/log-drop/cache-hit/origin-error, snapshot version/age/stale, mTLS expiry, goroutine và heap gauges. Cache hit có hook metric/log, nhưng cache response chưa có trong request pipeline hiện tại.
- Shipper dùng channel bounded không chặn (4096 record mặc định); mỗi request đưa stats delta qua queue để worker tổng hợp, không giữ global aggregation lock trên request path. Batch tối đa 1000 record, 1 giây hoặc 512 KiB JSON thô, zstd trước publish. Queue hoặc delivery lỗi làm drop và tăng `edge_log_dropped_total`; không có durable local spool. NATS mặc định `nats://127.0.0.1:4222`, subject `edge.logs.v1`; có thể dùng HTTPS ingest qua `EDGE_INGEST_URL` thay thế.
- Security event luôn được chọn; event thường lấy mẫu theo plan mặc định Free 1%, Pro 10%, Business 50%, Enterprise 100% (cấu hình qua `ShipperConfig.PlanSampleRate`). `site_stats_1m` tính từ mọi request delta được queue nhận, không phụ thuộc event sampling; queue overflow được đếm và có thể làm thiếu số tổng hợp. Cache hit được tính khi event có tag nội bộ `cache_hit`.
- Schema payload gồm `wafcore.LogEvent`/`wafcore.SiteStats1m`; schema không có body, Authorization hoặc Cookie, URL query không được log. IP được mask mặc định IPv4 /24 và IPv6 /56, cấu hình bằng `EDGE_LOG_IP_MASK_V4_BITS`/`EDGE_LOG_IP_MASK_V6_BITS`. Path/host/tag có giới hạn kích thước để giữ batch bounded.
- Tracing dùng OpenTelemetry `TraceIDRatioBased(0.001)`, chỉ ghi method/status và inject W3C Trace Context tới origin. Nếu `OTEL_EXPORTER_OTLP_ENDPOINT` không cấu hình, sampler hoạt động nhưng span không được export; endpoint HTTP(S) bật exporter OTLP/HTTP.
- NATS integration test chạy qua NATS server thật được CI cung cấp; proxy test đóng các TCP session để mô phỏng mất đường truyền rồi mở lại. Chưa có test điều khiển dừng tiến trình NATS server; delivery khi mất kết nối là best-effort, không có spool bền vững.

## Control Plane — schema/auth/tenant/entitlement — 2026-11-24

- Ứng dụng sinh mọi ID bằng UUIDv7 (`google/uuid.NewV7`); migration không đặt UUID default để không âm thầm tạo UUIDv4. Plan seed dùng UUIDv7 cố định để có thể tham chiếu Free trong luồng đăng ký.
- `waf_api` là role `NOLOGIN NOBYPASSRLS`; login ứng dụng phải được cấp membership role này. `db.Open` từ chối superuser, role có `BYPASSRLS`, hoặc login không thuộc `waf_api`. `waf_worker` là credential/role riêng có `BYPASSRLS` cho tác vụ toàn tenant; production cần giới hạn credential và ghi audit cho tác vụ đó. Goose migration phải chạy bằng role quản trị riêng.
- Mỗi transaction tenant gọi `SET LOCAL app.tenant_id`; policy RLS áp dụng `USING` và `WITH CHECK` trên mọi bảng có `tenant_id`. Truy vấn dịch vụ vẫn gắn tenant khi thuận tiện; RLS là lớp chặn nếu handler quên điều kiện tenant. `lookup_invitation` là hàm SECURITY DEFINER hẹp để tra token SHA-256 ngẫu nhiên; hàm khóa hàng invitation và chỉ trả metadata tối thiểu để redeem token một lần.
- Audit log được cấp quyền INSERT-only cho API/worker; không cấp SELECT/UPDATE/DELETE. Các mutation registration, invitation, membership và API key ghi audit trong cùng transaction.
- Bảng quota §5.15 không đặt giới hạn số site. Giữ ví dụ §5.3 cho Free=1/Pro=5 và chọn Business/Enterprise không giới hạn (`-1`) tạm thời; cần nhóm sản phẩm xác nhận. Giá gói seed bằng 0 USD vì bảng quota không chốt giá.
- Redis không truy cập được thì API rate limit trả 503 và login không tiếp tục không giới hạn. Refresh token cookie và CSRF double-submit đều `HttpOnly; Secure; SameSite=Lax`; login/refresh trả giá trị CSRF trong JSON để client giữ trong memory và gửi header.
- TOTP secret mã hóa AES-GCM bằng khóa từ `TOTP_ENCRYPTION_KEY`; JWT Ed25519 ký bằng `JWT_ED25519_PRIVATE_KEY`; đây là cấu hình dev/runtime interface, không phải adapter KMS production. JWT hiện gắn `kid=cp-1` cố định.
- **TODO-CP-1:** Mailhog chỉ là adapter dev. SMTP production cần TLS, transactional outbox/retry và luồng gửi lại verification; hiện gửi sau commit nên SMTP lỗi không rollback tài khoản đã tạo.
- **TODO-CP-2:** xác minh migration thực trên PostgreSQL, RLS dưới login API, Redis lockout và Mailhog chỉ hoàn tất sau CI/WSL integration xanh. Máy Windows lượt này không có Docker daemon hoặc loopback services; không đánh dấu migration integration đã chạy.

## P7-verify — phân quyền dữ liệu xác thực

- `waf_api` là role nhóm `NOLOGIN NOBYPASSRLS`. API login runtime phải là role không superuser và không `BYPASSRLS`, chỉ được cấp membership `waf_api`. Các bảng user và credential/token bật `ENABLE` + `FORCE RLS`; `users.id` phải khớp `app.user_id`, các bảng token/session/recovery lọc theo `user_id`. GUC được gán trong transaction (`set_config(..., true)`); `current_setting(..., true)` + `NULLIF` khiến thiếu context chỉ trả không hàng.
- `waf_worker` là role nhóm `NOLOGIN BYPASSRLS`, không superuser. Chỉ job nền/back-office được dùng login riêng sau khi provision; không dùng nó trong API. Audit log append-only. Trigger trên user/session/recovery/reset/verification ghi audit khi có mutation và không sao chép secret/hash vào diff; tenant actions ghi audit cùng transaction. Mọi truy vấn trực tiếp của worker cần entrypoint có audit; PostgreSQL RLS không ghi audit cho SELECT tùy ý, nên chưa cấp credential worker cho tới khi audit policy được provision (TODO-CP-2 / TODO-P7V-3).
- `SECURITY DEFINER` chỉ do `waf_worker` sở hữu, `search_path=pg_catalog, public`, bảng/function tham chiếu schema-qualified, quyền mặc định PUBLIC bị thu hồi; chỉ `waf_api` được `EXECUTE` các entrypoint cần thiết. Không cấp `waf_api` quyền cột credential/token hash hay quyền INSERT/UPDATE trực tiếp trên bảng auth. `tenant_list_members` là giao diện hẹp (ID, email, role, created_at), không mở `users` chéo tenant.
- Danh sách hàm definer và mục đích: `auth_register_user` tạo user/org/owner/subscription/verification trong một lệnh; `auth_login_material` lấy trường tối thiểu để Argon2/TOTP login; `auth_consume_email_verification` tiêu thụ token một lần; `auth_create_refresh`, `auth_rotate_refresh`, `auth_logout_refresh` tạo/đổi/thu hồi session, đổi refresh khóa hàng và phát hiện replay; `auth_password_reset_request`, `auth_complete_password_reset` tạo/tiêu thụ reset token và thu hồi session; `auth_configure_totp`, `auth_totp_secret`, `auth_consume_totp_step`, `auth_enable_totp`, `auth_consume_recovery_code` cài/đọc/tiêu thụ TOTP theo user hiện tại; `tenant_create_api_key` và `tenant_create_invitation` ghi hash + audit, `tenant_accept_invitation` redeem token khóa hàng/ràng buộc email, `tenant_list_members` trả metadata hẹp; `lookup_invitation` là helper tương thích, chỉ trả metadata và đã được ghim search_path; `audit_auth_mutation` ghi audit cho mutation bảng auth. Hàm ghi nhận ID được Go sinh UUIDv7; trigger dùng `uuidv7()` của PostgreSQL 18.
- Reset/login không lộ trạng thái email: login chạy cùng Argon2 cost với hash giả khi email không tồn tại; reset luôn trả phản hồi generic, enqueue cùng dạng thư cho địa chỉ nhập vào, và có timing floor. Email được đưa vào hàng đợi RAM bounded; durable outbox/retry vẫn là TODO-CP-1.
- TOTP lưu `totp_last_step`; hàm consume chỉ nhận bước trong cửa sổ hiện tại ±1 và chỉ tăng step, nên một mã không thể dùng lại trong cùng tài khoản.
- Migration `00002` bổ sung quyền mà không sửa `00001`. PostgreSQL 18 được yêu cầu cho UUIDv7 trong audit trigger. Test schema so sánh mọi bảng `public` không RLS với allowlist rõ lý do: `plans`, `config_snapshots`, `edges`, `webhook_events`, `goose_db_version`.
- **TODO-CP-2:** provisioning riêng login `waf_api`/`waf_worker` và migration role có `CREATEROLE` (không superuser) + membership `waf_worker` để đổi owner; migration CI hiện chạy bằng superuser của PostgreSQL service. Không bật login worker trước khi có audit policy cho truy vấn trực tiếp.
- **TODO-P7V-1:** chỉ đánh dấu P7-verify hoàn tất sau khi CI `cp-integration` trên PostgreSQL 18 chạy `-race -count=20`, không SKIP, và xanh. WSL/PostgreSQL 18.6/Redis 8.0.5 integration đã chạy xanh cục bộ; GitHub Actions cho commit mới chưa được quan sát.

## P7-close — binding danh tính khi tạo refresh session

- Migration `00003_refresh_identity_guard.sql` thay thân `auth_create_refresh` mà không sửa migration đã phát hành. Hàm yêu cầu `app.user_id = p_user_id`, khóa đọc user đang `active`, rồi mới INSERT refresh token. Session mới luôn tạo audit `auth.session.create`, actor là user; `tenant_id` lấy từ `users.default_tenant_id` (org cá nhân), NULL chỉ khi schema cho phép user chưa gắn org. Refresh session không được tạo cho user inactive hoặc không có session identity.
- Login theo thứ tự lấy `auth_login_material(email)` → verify Argon2 → kiểm tra TOTP/recovery → `WithUserTx(user_id đã xác minh)` → `auth_create_refresh`. Không dùng user ID từ request. Registration hiện không phát session; mọi đường tạo refresh session đều qua hàm trên. Mã kiểm thử xác nhận gọi chéo ID và thiếu session bị từ chối, không thêm row; đăng nhập hợp lệ tiếp tục tạo session và audit.
- **Giới hạn session GUC:** `app.user_id`/`app.tenant_id` chống lỗi logic ứng dụng (IDOR, thiếu WHERE, handler truyền nhầm ID), nhưng không chống SQL tùy ý chạy dưới login `waf_api`, vì SQL đó có thể tự `SET LOCAL app.user_id`. Dùng truy vấn tham số hóa/sqlc; CI kiểm tra tĩnh cấm nối chuỗi SQL và dynamic SQL trong controlplane; audit mọi session creation, rate-limit login/session, giám sát bất thường. **TODO-P7C-1:** ngữ cảnh DB có chữ ký (ứng dụng ký user ID + expiry, hàm DB xác minh) trước khi cần phòng thủ trước SQL injection đã thực thi.
- `auth_register_user` chỉ nhận ID mới do registration sinh và tạo một user + org cá nhân + membership owner + subscription; uniqueness/FK làm ID trùng lỗi, hàm không tham gia org hiện hữu. `auth_login_material` trả material tối thiểu theo email; trường hợp không có user được Go xử lý bằng Argon2 dummy hash cùng cost.

| Hàm `SECURITY DEFINER` | Nguồn danh tính / kiểm tra | Dữ liệu trả về hoặc tác động |
|---|---|---|
| `auth_register_user` | UUID mới của luồng đăng ký; insert-only, ID/email conflict lỗi | Tạo user và org cá nhân cùng token xác minh; không join org có sẵn |
| `auth_login_material` | Email tra cứu; Go xác minh password, TOTP sau đó | User ID, hash password, status, tenant, TOTP material cần thiết |
| `auth_create_refresh` | `app.user_id` phải bằng ID; user tồn tại và active | Tạo session của chính user và audit event |
| `auth_rotate_refresh`, `auth_logout_refresh` | Khả năng sở hữu refresh-token hash; rotate khóa hàng và thu hồi family | Outcome/user metadata hoặc thu hồi đúng session/family |
| `auth_consume_email_verification`, `auth_complete_password_reset` | Token hash bí mật + hạn + unused | Boolean; tiêu thụ token, cập nhật trạng thái/password, thu hồi sessions |
| `auth_password_reset_request` | Email yêu cầu; không trả tồn tại hay không | Tạo token chỉ khi user khớp; HTTP/service luôn generic |
| `auth_configure_totp` | `app.user_id` phải bằng tham số user | Chỉ cập nhật secret/recovery code của user hiện tại |
| `auth_totp_secret`, `auth_consume_totp_step`, `auth_enable_totp`, `auth_consume_recovery_code` | `app.user_id`; consume kiểm step/hash của user hiện tại | Chỉ material mã hóa của user hiện tại hoặc boolean |
| `tenant_create_api_key` | `app.tenant_id` + `app.user_id` khớp tham số; membership owner/admin; scopes allowlist | Ghi key hash và audit; không trả plaintext key |
| `tenant_create_invitation` | Session tenant/user khớp; owner/admin; role chỉ admin/viewer | Ghi invitation hash và audit |
| `tenant_accept_invitation` | `app.user_id` khớp user; email user khớp invitation + token hash | Chấp nhận invitation một lần, tạo membership user hiện tại |
| `tenant_list_members` | User từ `app.user_id`, tenant từ `app.tenant_id`, membership tồn tại | Metadata directory giới hạn (ID/email/role/created_at) |
| `lookup_invitation` | Token hash possession; row khóa; output metadata hẹp | Chỉ ID/tenant/email/role để kiểm tra token; không mutation |
| `audit_auth_mutation` | Trigger lấy actor/tenant từ row đã đổi; không callable nghiệp vụ | Ghi operation/entity ID, không ghi secret/hash |

Integration test đối chiếu mọi hàm `SECURITY DEFINER` với allowlist này bằng inventory trong test, kiểm `search_path`, owner `waf_worker` không-superuser, không có EXECUTE cho PUBLIC hay role ngoài owner/`waf_api`. Mọi hàm mới không được thêm allowlist sẽ làm test fail.

## P8a-fix — test chạy lặp lại và hostname chuẩn hóa

- Hostname domain được chuẩn hóa bằng IDNA Lookup profile sang lowercase ASCII trước insert. U-label, punycode, khác biệt hoa/thường và dấu chấm cuối cùng vì vậy tranh chấp cùng một khóa toàn cục.
- Chỉ lỗi PostgreSQL `23505` trên constraint `domains_hostname_key` được ánh xạ sang phản hồi generic `hostname is unavailable`; lỗi unique khác được giữ nguyên.
- Tích hợp CP dùng UUID/email/hostname riêng cho mỗi lượt và dọn tenant/user, row phụ thuộc cùng Redis login throttle key bằng cleanup. CI giữ `-count=20` trên cùng service database để phát hiện phụ thuộc vào DB rỗng.
- Proxy loopback test dùng DNS giả trả một IP tài liệu công khai và dialer riêng của test ánh xạ IP đã được netguard xác minh sang httptest origin. Cấu hình/env/snapshot production không có tùy chọn tắt guard; kiểm tra mặc định vẫn từ chối loopback, private, metadata, CGNAT và ULA.
- **Chưa xác minh trên Linux:** sandbox hiện tại là Windows; `wsl.exe` và Docker daemon đều bị từ chối/không khả dụng, nên các test loopback và integration thật cần chạy lại trong WSL/CI.

## P8a-fix-2 — dọn fixture cùng schema coverage

- Integration cleanup chạy các lệnh xóa trong transaction quản trị duy nhất; từng lệnh giữ argument riêng và savepoint để gom mọi lỗi SQL, commit phần đã dọn rồi báo toàn bộ lỗi có câu SQL. Thứ tự xử lý con trước cha; role đăng nhập tạm được revoke/drop bằng cleanup riêng và lỗi được báo.
- Schema test duyệt mọi bảng `public`: bảng có `tenant_id`, `user_id`, `actor_id` hoặc `created_by` phải nằm trong cleanup coverage; bảng toàn cục chưa có fixture key phải có allowlist và lý do (`plans`, `config_snapshots`, `edges`, `webhook_events`, `goose_db_version`).
- `make check-generated` là cùng một cổng local/CI: gofmt không còn file, `go mod tidy`, `make gen`, `git diff --exit-code`; `make check-cp-sql` chạy riêng ngay sau trong CI.
- **Chưa xác minh:** không truy cập được WSL/Linux, Docker/Postgres/Redis trong phiên này, nên không có kết quả `make check-generated` hay integration DB thật để xác nhận.
- Local Windows đã xác nhận gofmt rỗng, `go mod tidy` exit 0, golangci-lint `0 issues`, `go vet`/`go build` exit 0 và integration package compile. Race cần CGO; `make` không cài; oapi/sqlc generation cùng govulncheck bị chặn bởi DNS; SQL checker/WSL bị `E_ACCESSDENIED`. Các kết quả này không thay thế chạy `make check-generated` và hai lượt Postgres integration trên Linux.

## P8a-fix-3 — xóa tenant và audit trail

- **TODO-CP-3 / chính sách đã chọn:** khi hết retention/legal hold và tenant yêu cầu erasure, worker sẽ xóa dữ liệu tenant theo lô; trong PostgreSQL xóa `audit_logs` theo `tenant_id` sau các bảng có trigger, nhưng trước `organizations`. Giữ FK `RESTRICT` trong thời gian dữ liệu tồn tại để không tạo audit mồ côi; không dùng `ON DELETE SET NULL` vì sẽ mất quan hệ audit trong kỳ retention.
- Trigger `audit_auth_mutation` hiện ghi một event cho mỗi token/recovery row bị xóa. Với user erasure theo lô, chọn ghi một sự kiện tổng hợp `tenant.erase` vào audit vận hành toàn cục rồi bỏ qua audit từng row của thao tác xóa có kiểm soát; không bỏ trigger bằng `session_replication_role`. Cần thiết kế entrypoint worker có phân quyền hẹp, batch/retry, redaction và test khối lượng trước khi triển khai; hiện chưa có luồng erasure production.
- Integration cleanup hiện không giả lập quyền xóa hàng loạt của production. Test fixture tạo refresh/reset/TOTP recovery, token, audit, outbox, site/domain; xác nhận 10 recovery-code insert events, rồi chạy cleanup lặp lại dưới cả superuser và role `BYPASSRLS` không-superuser. Test thứ tự planner đặt audit cuối cùng trước organization, kể cả khi chèn thêm cleanup statement cho bảng có audit trigger.

## P8a-fix-4 — trạng thái site trong tranh chấp hostname

- Kết quả `AddDomain` trong cuộc đua gắn domain với site được truyền vào request thắng duy nhất. Site mới bắt đầu `pending_dns`; thêm domain hoặc origin không kích hoạt site. Khi DNS proof của domain được xác minh, worker chuyển domain sang `active` và chỉ site sở hữu domain đó từ `pending_dns` sang `active`. DNS proof hết hạn chuyển domain sang `failed`, không đổi trạng thái site.
- Lỗi kiểm tra trước đây giả định site của tenant A luôn thắng. Với hai request đồng thời trên hai site, tenant B có thể thắng hợp lệ; xác minh sẽ kích hoạt site B trong khi site A vẫn `pending_dns`. Test nay mang site ID cùng kết quả mỗi request và kiểm tra winner active/loser pending, không thay đổi code production hay nới lỏng assertion.
- **Chưa xác minh bằng PostgreSQL trong lượt này:** sandbox không truy cập WSL, DB hoặc GitHub Actions. Cần xác nhận lại test với `-count=100 -race` và hai lượt CP integration `-count=20` trên cùng DB.

## P8b — snapshot publisher/distribution MVP

- Worker đọc transactional outbox theo lô với `FOR UPDATE SKIP LOCKED`, phát NATS `config.changed`, rồi debounce 3 giây và đọc site/config/rule/quota trong transaction PostgreSQL `REPEATABLE READ READ ONLY`. API không cần đợi NATS sau khi commit cấu hình. Nếu worker crash sau publish nhưng trước khi đánh dấu outbox, sự kiện có thể phát lại; debounce/build từ trạng thái DB mới khiến việc phát lại idempotent về snapshot.
- Version dùng sequence toàn cục `config_snapshot_global_version_seq` (migration `00005`), checksum SHA-256 và chữ ký Ed25519 qua SecretStore. Key là `snapshots/<region>/<version>.json.gz`; hàng active trong `config_snapshots` là con trỏ latest theo vùng; publisher giữ 50 bản gần nhất. Theo định dạng edge hiện tại, object là signed JSON envelope, còn payload bên trong envelope được gzip.
- GET `/internal/snapshot?edge_id=...&since=...` yêu cầu TLS client certificate đã verify, đối chiếu serial với edge active/ready và đối chiếu edge_id; hỗ trợ ETag/304. Worker phát NATS `config.updated`. Contract test build, verify và nạp snapshot vào edge core thật, chạy self-test và serialize `wafcore.LogEvent`; test khác kiểm debounce burst.
- Rollback phải build nội dung cũ dưới version mới từ sequence toàn cục; edge chỉ nhận version lớn hơn version đang áp dụng. Không lùi con trỏ latest. Hai publisher cùng vùng tuần tự hóa reservation/publish bằng advisory transaction lock, publisher hoàn tất trễ bị từ chối bằng `ErrStaleBuild`. Chữ ký sai, `kid` lạ, replay version thấp/equal không thay bản đang chạy.
- Endpoint mTLS ràng buộc chứng thư đã đăng ký theo serial với edge ID trong CN, DNS SAN hoặc URI SAN `/edges/<edge-id>`; yêu cầu `edge_id` phải khớp cùng danh tính. Không chỉ dựa vào tham số query do client gửi.
- **TODO-P9A-1:** chỉ có `FileObjects` atomic local dev/test; chưa có S3-compatible implementation/SDK ghim hoặc test object store thật. Secret signing key hiện nạp từ env vào Memory SecretStore, chưa có backend KMS production.
- **TODO-P9A-2:** schema site chưa có region/placement nên hiện mỗi region đọc cùng tập site; thêm placement trước khi bật nhiều vùng.
- **TODO-P9A-3:** canary nhóm edge, heartbeat threshold, tự dừng/rollback và endpoint rollback chưa có; hiện publish latest áp dụng cho toàn vùng. Chưa có test canary, rollback giữa chừng hoặc mất kết nối lúc rollout.
- **TODO-P9A-4:** chưa mã hóa envelope bí mật riêng theo edge, chưa có kênh emergency signed+nonce, và chưa có quy trình enrollment cấp cert/ghi serial; endpoint chỉ ánh xạ chứng thư đã đăng ký.
- **TODO-P9A-5:** chạy migration/worker với Postgres, NATS, mTLS và S3 thật; thêm kiểm thử chaos và đo rule-save→edge-apply trong Linux. Contract test in thời gian đo được bằng `-v`, nhưng phiên Windows hiện không cung cấp kết quả Linux/CI.
- **TODO-P9A-6:** outbox dispatcher là at-least-once: crash sau khi NATS nhận publish nhưng trước commit có thể phát trùng. Consumer debounce/build từ trạng thái DB mới nên hiệu ứng snapshot idempotent; chưa có JetStream durable dedupe/Msg-Id hoặc test crash giữa publish/commit chứng minh exactly-once.

## P9b — fleet và certificate MVP

- Bootstrap token sinh ngẫu nhiên, chỉ lưu SHA-256, hết hạn sau một giờ và tiêu thụ bằng một `UPDATE ... RETURNING` nguyên tử. CSR phải có chữ ký hợp lệ; CP tự đặt edge ID trong CN và URI SAN, không tin tên trong CSR. Đăng ký nằm trên worker nội bộ và dùng HTTPS + token một lần vì edge chưa có chứng chỉ mTLS trước khi bootstrap; API công khai không mở route đăng ký.
- Heartbeat chấp nhận danh tính từ client certificate mTLS đã được listener xác minh, rồi kiểm tra serial trong `edge_certificates`. Edge được đánh dấu ready/degraded theo health payload; stale heartbeat được hạ trạng thái qua sweeper. DNS yêu cầu 3 quan sát liên tiếp; sweeper rút tối đa 1 edge/region mỗi phút và không rút edge cuối. Thu hồi do compromise có ưu tiên an toàn: chặn certificate trước, rồi thử rút DNS; lỗi DNS được báo nhưng không khôi phục certificate.
- Các bảng fleet toàn cục (`edges`, `edge_certificates`, `edge_bootstrap_tokens`, `certificate_issuance_rate_limits`, `edge_dns_withdrawal_limits`) chỉ cấp quyền tối thiểu cho `waf_worker`; `waf_api` và `PUBLIC` không có quyền đọc/ghi. Worker sở hữu snapshot, heartbeat, renewal và enrollment. API công khai không truy vấn các bảng này trực tiếp.
- Worker lấy CA private key qua `secret.Store`. Development mặc định sinh CA chỉ trong RAM; khi dùng file cấu hình, key phải ở ngoài repo và Linux mode `0400` hoặc `0600`. Giá trị key không được đưa qua env, log, snapshot hay DB. Store đang dùng là in-memory, nên production cần backend bền vững/HSM và quy trình phân phối/rotation.
- Edge certificate cũ còn hiệu lực trong cửa sổ rotation sau khi cấp certificate mới; endpoint mTLS heartbeat/renew đã có, nhưng edge client chưa tự gọi renew.
- Certificate manager có `ACMEIssuer`, `FakeIssuer`, rate limit và khóa trùng issuance theo domain trong tiến trình; renewal scan dưới 30 ngày, exponential backoff tối đa 24 giờ, cảnh báo khi lần renew lỗi và certificate còn dưới 14 ngày. Private key và certificate được giữ dưới hai SecretStore refs; DB chỉ có ref. Fake issuer dùng trong test. Provider production lego/certmagic, HTTP-01 emergency publisher, DNS-01, durable SecretStore, customer upload endpoint/entitlement, phân phối leaf cert qua snapshot mTLS và site-delete hook chưa được tích hợp.
- Cloudflare/Route53 là stub có lỗi rõ khi chưa cấu hình; DNS fake phục vụ test. Không xem stub hoặc in-memory SecretStore là production-ready.

## P9b-fix-1 — cô lập quyền fleet và dọn fixture

- Migration mới `00007_restrict_fleet_tables.sql` thu hồi mọi quyền trên năm bảng hạ tầng khỏi `waf_api` và `PUBLIC`, sau đó chỉ cấp `SELECT/INSERT/UPDATE` cần thiết cho `waf_worker`. Migration `00006` không được sửa vì đã có thể chạy ở môi trường dùng chung.
- Route `POST /internal/edges/register` được gỡ khỏi API công khai và chạy trong worker với pool `waf_worker`; worker bind loopback mặc định và triển khai phải chỉ bind interface nội bộ/firewall. Bootstrap dùng HTTPS + token một lần; heartbeat, renewal và snapshot yêu cầu chứng chỉ client đã verify. Đây là ngoại lệ bootstrap có chủ đích: bắt buộc mTLS trước khi cấp chứng chỉ sẽ tạo vòng lặp không thể đăng ký edge mới.
- Integration cleanup theo dõi edge UUID, region và issuer key do fixture tạo; dọn `edge_bootstrap_tokens`, `edge_certificates`, `edges`, DNS cooldown và issuer rate limit bằng pool quản trị. Kiểm tra privilege thử đủ SELECT/INSERT/UPDATE/DELETE dưới login `waf_api`; không sửa logic/assertion của RLS allowlist ngoài việc khai báo các bảng fleet worker-only đã thiết kế.
- Retry timestamp làm tròn lên microsecond trước khi ghi PostgreSQL để precision `timestamptz` không rút ngắn backoff. Root cause phù hợp với log `attempts=1`: kiểm tra retry schedule thất bại sau khi hàng retry đã được ghi; so sánh trước đây dùng thời điểm Go nanosecond trong khi DB lưu microsecond.
- CA key được chuyển qua `secret.Store`; file input phải nằm ngoài repo và mode `0400`/`0600` trên Linux. **TODO-P9B-8:** thay in-memory store bằng SecretStore bền vững/HSM, xác minh test quyền file/CA và key rotation trên Linux.
- **Chưa xác minh ở lượt sửa này:** PostgreSQL/Redis/NATS thật, migration `00007` up/down/up, hai lần `-race -count=20`, make check-generated, govulncheck, SQL guard và GitHub Actions. Cần chạy theo lệnh trong `docs/PROGRESS.md` trên WSL/Linux.

## P9b-verify — decision log

- `certificates.secret_ref` là tham chiếu nội bộ tới vật liệu trong SecretStore, không phải metadata khách hàng. Migration `00008_hide_certificate_secret_refs.sql` thu hồi SELECT bảng certificates khỏi PUBLIC và waf_api; hiện chưa có API chứng chỉ công khai. Test integration kiểm tra cột nhạy cảm đọc được phải khớp allowlist rỗng, và model `CertificateStatus` không serialize `secret_ref`. Migration chỉ đổi grants, không đổi schema; sqlc output không có thay đổi cần sinh.
- Snapshot phải xác nhận cả `edges.cert_serial` lẫn hàng `edge_certificates` active, chưa hết hạn; trạng thái edge sẵn sàng và không compromised. Resolver trước đó chỉ tra edges, do đó certificate bị revoke riêng lẻ vẫn được chấp nhận nếu edge status chưa đổi. Regression test yêu cầu từ chối.
- Worker bind địa chỉ không-loopback chỉ với `WORKER_ALLOW_NETWORK=true`; listener dùng TLS. Nếu chưa đặt cờ, chỉ localhost/loopback được phép. Worker vẫn dùng `waf_worker` BYPASSRLS cho cả internal endpoints và background jobs. **TODO-P9B-9:** tách `waf_fleet` NOBYPASSRLS, grants hẹp và credential/listener riêng; rủi ro hiện tại là handler internal bị xâm nhập có thể sử dụng đặc quyền nền rộng.
- Snapshot builder khi gói entitlement có JS challenge nhưng thiếu key reference sẽ giữ site, tắt challenge (mode monitor), và phát warning; không loại site. Đây là hạ cấp an toàn cho một tính năng tùy chọn, không làm region snapshot lỗi.

## P10 — ingest, analytics, reference data (MVP)

- Ingest uses edge envelope `schema_version=1`, zstd decode bounded to 4 MiB compressed / 32 MiB decoded / 10,000 rows. `wafcore.LogEvent.Validate` and `SiteStats1m.Validate` run before storage. Tenant ID from edge is overwritten by the canonical `site_id → tenant_id` policy read; Redis caches that Postgres-derived mapping and plan retention for 30 seconds. Unknown/inactive site is rejected.
- ClickHouse uses the documented `security_events` and `site_stats_1m` column schemas via HTTP `JSONEachRow`; event insert includes plan `retention_days`. Queue is bounded (4096), flushes at 1 second or 10,000 rows. Invalid payloads and failed inserts enter a local append-only JSONL dead-letter file (0600, directory 0700). Production must set `INGEST_DLQ_PATH` to persistent protected storage. Queue full on HTTP returns 503; NATS queue overflow is counted and sent to dead-letter. Event request IDs duplicated within one envelope are collapsed. Multi-envelope redelivery dedupe and exactly-once stats remain unresolved because the edge envelope has no stable batch ID.
- HTTP ingest requires a verified client certificate; production NATS also requires client cert + CA. Development NATS may be plaintext. Worker DB role currently supplies the site/plan read. ClickHouse URL/query values are parameterized; analytics SQL has fixed tenant_id and site_id predicates. API checks site ownership and retention window against Postgres using tenant_id from authenticated principal; request timeout is 2 seconds, row limit 500, Redis cache 20 seconds.
- Reference-data updater is an interface-based MVP: HTTPS-only guarded fetch, explicit redistribution license metadata, bounded size, CIDR/MMDB/managed-rule validation, normalization and change-anomaly guard. No vendor feed is enabled by default until its current license terms/credentials are reviewed. Scheduler wiring, durable version repository, snapshot publishing adapter and warning persistence remain TODO; do not claim blocklists/GeoIP/rules have been rolled out.
- ClickHouse inserts across two tables are not transactional. If security_events succeeded but site_stats_1m failed, only stats rows are dead-lettered to avoid replaying the successful event insert. ClickHouse deduplicates duplicate request IDs only inside a single input envelope; cross-message replay and duplicate stats are possible.
