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
- CI chạy tuần tự lint → test → govulncheck; dependency Go ghim phiên bản trong `go.mod`/`go.sum`.

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

## Quyết định P3 — access và rate limiting

- Access IP dùng binary radix trie bất biến sau khi dựng, tách IPv4/IPv6. Thứ tự là allow IP → ban tạm/block IP → country/ASN → global blocklist → hook Under Attack. Allow-list thắng ban để giữ đường khôi phục quản trị.
- Entitlement access lấy theo `site.plan`: Free cho IP/CIDR, Pro thêm country, Business/Enterprise thêm ASN. Cấu hình vượt gói bị fail-closed và trả `RuleID=access_config`.
- Geo/ASN dùng `maxminddb-golang` với `Reader` memory-map; đường dẫn nhận từ `EDGE_GEOIP_COUNTRY_MMDB`/`EDGE_GEOIP_ASN_MMDB`, file dữ liệu do operator cung cấp. Kết quả được cache trong `RequestCtx`; resolver lỗi hoặc không có database mặc định fail-open riêng phần Geo/ASN, các lớp IP/global vẫn chạy.
- Global blocklist hiện nạp CIDR qua `EDGE_GLOBAL_BLOCKLIST_CIDRS` làm adapter khởi đầu; danh sách chuẩn có chữ ký trong snapshot/ConfigSync và feed từ CP là TODO. Under Attack đang là interface stub tắt mặc định.
- Rate limit mặc định `token_bucket`, capacity đầy ở request đầu, dùng micro-token và CAS trên atomic pointer; có thể chọn `sliding_window` bằng trường `algorithm`. Key được SHA-256 trước khi lưu; bảng shard có trần toàn cục 100.000 key mặc định, áp dụng thêm `entitlements.max_counter_keys` theo site, TTL hai giờ mặc định và dọn dần theo batch.
- Redis là lớp phân tán eventual: local limiter luôn quyết định không chờ mạng; counter được xếp hàng bounded và chạy Lua `INCR`/`PEXPIRE` theo batch. Kết quả Redis được cache để các request tiếp theo chặn khi ngưỡng toàn cục đã vượt; Redis/queue lỗi thì bỏ qua cache Redis, quay về local. Batch queue đầy có thể mất đồng bộ, không chặn request.
- Key hỗ trợ: `ip`, `ip+path`, `header:<name>`, `cookie:<name>`, `ja3`, `site`. Action `block`/`throttle` trả 429 + Retry-After; `challenge` trả challenge; `ban_s` thêm IP vào ban table TTL. `rule_id` có trong Decision của RequestCtx và log rate-limit.
