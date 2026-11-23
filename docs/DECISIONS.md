# Quyết định kiến trúc P0

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

- Metrics được đưa sau interface `pipeline.Metrics`; bản đầu tự xuất Prometheus text format để tránh thêm dependency ngoài trong môi trường chưa có mạng. Histogram pha, counter chặn và `log_dropped` không dùng `site_id` làm label toàn cục. Khi dependency được phép tải, thay lớp xuất bằng `client_golang` mà giữ interface này.
- PROXY protocol hiện chỉ hỗ trợ v1 và chỉ nhận từ CIDR tin cậy. TODO: thêm v2 để tương thích NLB.
- JA3/JA4 hiện là `Fingerprinter` stub trả chuỗi rỗng. TODO: triển khai fingerprint ClientHello và kiểm thử tương thích.
- Snapshot production luôn phải qua Ed25519 verify theo `kid`; unsigned local JSON/YAML chỉ được bật ngoài production với `EDGE_DEV_UNSIGNED=1`. Keyring nhận nhiều mục qua env hoặc file.
- DNS origin được kiểm tra khi nạp cấu hình và resolve/recheck ngay trong dial để chống DNS rebinding. Chuẩn hóa domain hiện hỗ trợ lowercase, port/trailing dot và punycode cơ bản; TODO: UTS #46 đầy đủ nếu yêu cầu domain quốc tế hóa nâng cao.
- Certificate mặc định tự ký chỉ để khởi tạo listener và hoàn tất TLS handshake; router vẫn từ chối Host không khớp SNI. Chứng chỉ production được nạp từ file; phân phối certificate qua kênh mTLS CP↔edge còn chờ phần tích hợp control plane.

## Quyết định P4d — WAF budget và fail mode — 2026-11-23

- WAF kiểm tra theo thứ tự URI path → query → header chọn lọc → cookie → body. Giới hạn triển khai hiện tại là 4 KiB trên toàn request, 2 KiB mỗi mục tiêu và 1 KiB body prefix; query parse giới hạn 8 KiB / 64 tham số. Đây là trần xử lý, không phải chỉ cảnh báo sau khi quét xong.
- Body được buffer tối đa theo hai trần: entitlement/site và WAF prefix; phần đã đọc được phát lại trước phần body chưa đọc để origin nhận stream đầy đủ. Nếu body bị cắt, không quét được hoặc lỗi khi đọc, gắn `waf_body_truncated` và cộng `truncated_body_score` (mặc định 3; 0 hoặc bỏ trống dùng mặc định, cấu hình 1–5), không xem request là sạch.
- Deadline 2 ms được kiểm tra giữa các mục tiêu, các bước normalize và nhóm luật. Khi vượt trần, giữ điểm đã cộng, gắn `waf_budget_exceeded` và áp fail mode. Việc đọc một `Request.Body` đang bị client giữ mở có thể chặn trong lệnh Read; giới hạn số byte không tự tạo deadline cho socket. Cần giới hạn đọc body ở listener/transport trước khi tuyên bố hard wall-clock bound.
- `fail_open` khi vượt ngân sách có rủi ro bỏ qua rule chưa kịp chạy; đó là lựa chọn mặc định cho Free để tránh từ chối nhầm, không phải bảo đảm WAF. Gói trả phí nên dùng `fail_mode=closed`; WAF mode `challenge` có thể dùng cho rule match bình thường, nhưng budget timeout vẫn áp dụng `fail_mode`. Cấu hình `site.fail_mode` tường minh luôn được tôn trọng.
- Audit WAF đi qua queue bounded, enqueue không chặn request; queue đầy thì bỏ sự kiện và tăng counter. Hiện writer mặc định là in-memory để quan sát/test, không bền vững qua restart. TODO-2: P6a thay adapter này bằng telemetry bền vững và xác minh giao nhận/dropped metrics.
- Corpus v2 đã bị xem khi tinh chỉnh nên được xem là dev, không phải held-out. Không dùng nó để chốt chất lượng; benchmark TPR/FPR trên thư mục corpus bên ngoài chỉ đánh giá file `attacks.tsv`/`clean.tsv` do người cung cấp, không nạp rules từ thư mục đó.

## Quyết định P3 — access và rate limiting

- Access IP dùng binary radix trie bất biến sau khi dựng, tách IPv4/IPv6. Thứ tự là allow IP → ban tạm/block IP → country/ASN → global blocklist → hook Under Attack. Allow-list thắng ban để giữ đường khôi phục quản trị.
- Entitlement access lấy theo `site.plan`: Free cho IP/CIDR, Pro thêm country, Business/Enterprise thêm ASN. Cấu hình vượt gói bị fail-closed và trả `RuleID=access_config`.
- Geo/ASN dùng `maxminddb-golang` với `Reader` memory-map; đường dẫn nhận từ `EDGE_GEOIP_COUNTRY_MMDB`/`EDGE_GEOIP_ASN_MMDB`, file dữ liệu do operator cung cấp. Kết quả được cache trong `RequestCtx`; resolver lỗi hoặc không có database mặc định fail-open riêng phần Geo/ASN, các lớp IP/global vẫn chạy.
- Global blocklist hiện nạp CIDR qua `EDGE_GLOBAL_BLOCKLIST_CIDRS` làm adapter khởi đầu; danh sách chuẩn có chữ ký trong snapshot/ConfigSync và feed từ CP là TODO. Under Attack đang là interface stub tắt mặc định.
- Rate limit mặc định `token_bucket`, capacity đầy ở request đầu, dùng micro-token và CAS trên atomic pointer; có thể chọn `sliding_window` bằng trường `algorithm`. Key được SHA-256 trước khi lưu; bảng shard có trần toàn cục 100.000 key mặc định, áp dụng thêm `entitlements.max_counter_keys` theo site, TTL hai giờ mặc định và dọn dần theo batch.
- Redis là lớp phân tán eventual: local limiter luôn quyết định không chờ mạng; counter được xếp hàng bounded và chạy Lua `INCR`/`PEXPIRE` theo batch. Kết quả Redis được cache để các request tiếp theo chặn khi ngưỡng toàn cục đã vượt; Redis/queue lỗi thì bỏ qua cache Redis, quay về local. Batch queue đầy có thể mất đồng bộ, không chặn request.
- Key hỗ trợ: `ip`, `ip+path`, `header:<name>`, `cookie:<name>`, `ja3`, `site`. Action `block`/`throttle` trả 429 + Retry-After; `challenge` trả challenge; `ban_s` thêm IP vào ban table TTL. `rule_id` có trong Decision của RequestCtx và log rate-limit.
