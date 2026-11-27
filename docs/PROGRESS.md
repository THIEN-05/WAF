# Tiến độ

## P8a — hardening site/domain/origin (chưa đóng) — 2026-11-25

### Đã xác minh cục bộ

- Migration `00004` mở rộng domain verification (method/status/hash expiry/next check), trạng thái site có CHECK + trigger cho chuyển hợp lệ; bảng `config_change_outbox` có `ENABLE` + `FORCE RLS` và policy `USING`/`WITH CHECK` theo `app.tenant_id`.
- Outbox grants: `waf_api` chỉ INSERT cột `id,tenant_id,site_id,payload`; `waf_worker` chỉ đọc các cột cần dispatch, INSERT payload cho event do worker tạo, và UPDATE `published_at,attempts,updated_at`. Regression integration test xác nhận RLS/force/policy/grants và allowlist các bảng không RLS; `config_change_outbox` không thuộc allowlist.
- `site_add_domain` là SECURITY DEFINER hẹp, owner `waf_worker`, fixed search_path, chỉ `waf_api` EXECUTE; buộc session tenant/user trùng tham số, membership owner/admin, site còn tồn tại, token digest SHA-256 và hạn tối đa 24 giờ; ghi audit trong cùng transaction. API không đọc/ghi cột hash trực tiếp. Conflict hostname được đổi thành lỗi chung `hostname is unavailable`.
- `netguard` nhận diện IPv4-mapped, CGNAT, link-local/metadata, ULA/loopback/unspecified và IPv4 inet_aton decimal/octal/hex/short forms; reject DNS answer set pha private/public; dial IP số đã kiểm tra. Edge và CP dùng package chung, không dùng environment proxy. `ProbeOrigin` có timeout/body cap, ngăn redirect và từ chối IP self-address; network isolation vẫn cần policy triển khai worker.
- Thêm worker batch API `VerifyDueDomains`: claim bounded bằng `FOR UPDATE SKIP LOCKED`, nhịp 1 phút trong 24 giờ rồi 15 phút, token compare constant-time, verification expiry, chuyển site/domain và enqueue outbox transactionally. Thêm integration tests PostgreSQL cho Free quota race, hostname race giữa tenants, hash privilege, worker verification, cross-tenant IDOR, outbox privilege, và state transitions.
- Unit tests: `go test ./pkg/netguard ./controlplane/internal/site ./controlplane/internal/api` → PASS; proxy security tests chọn lọc (`TestIsBlocked`, encoded IP/rebinding/dial pinning, no environment proxy) → PASS. `go test -tags=integration -run '^$' ./controlplane/internal/integration` → PASS biên dịch, `[no tests to run]`.
- `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0, không output; `go build ./...` → exit 0, nhưng Go báo Windows stat-cache `Access is denied`.
- `go test -count=1 ./...` → FAIL chỉ tại các test loopback Edge (`bot.TestLoopbackChallengeVerifyBodyReadDeadline`, `edgecore.TestLoopback*`, `listener.TestLoopback*`, `proxy.TestLoopback*`): Windows sandbox trả `connectex ... forbidden`; tất cả package CP và các package unit không cần loopback đều PASS. Không tính full suite là xanh.

### Chưa xác minh — không được coi là đóng phase

- Máy không nghe Postgres/Redis (`5432`/`6379` không có listener). Migration `00004` chưa được chạy trên DB trống theo up → down → up; integration tests không chạy trên PostgreSQL thật.
- Lệnh yêu cầu `CP_INTEGRATION_REQUIRED=1 go test -tags=integration -race -count=20 ./controlplane/internal/integration` thực tế dừng ở `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` (CGO_ENABLED=0). Cần chạy trong WSL/Linux với Postgres 18, Redis, quyền CREATEROLE và các service integration.
- `govulncheck ./...` không lấy được DB advisory: `lookup vuln.go.dev: no such host`; chưa xác minh vulnerability scan lượt này.
- `bash scripts/check-controlplane-sql.sh` bị Windows chặn tạo process: `Bash/E_ACCESSDENIED`; chưa xác minh SQL checker.
- Chạy lại trên WSL: `CP_INTEGRATION_REQUIRED=1 go test -tags=integration -race -count=20 ./controlplane/internal/integration`; `go test -race -count=1 ./...`; `govulncheck ./...`; `bash scripts/check-controlplane-sql.sh`. Với migration-cycle, dùng một database test rỗng riêng: `goose -dir controlplane/migrations postgres "$CP_MIGRATION_TEST_DATABASE_URL" up`, `down`, `up` (không dùng database có dữ liệu).

### Nợ kỹ thuật P8a

1. **TODO-P8A-DB-1:** chạy migration up/down/up và integration race trên Postgres/Redis thật; hiện mới biên dịch test, chưa có bằng chứng runtime.
2. **TODO-P8A-WORKER-1:** `VerifyDueDomains` có bounded claim/retry interval nhưng chưa được nối vào process `cmd/worker`; `ProbeOrigin` chưa được gọi bởi worker và chưa có network namespace/egress policy thực tế.
3. **TODO-P8A-OUTBOX-1:** chưa có dispatcher/retry/dead-letter; crash sau publish nhưng trước đánh dấu có thể tạo duplicate, do vậy chưa chứng minh exactly-once/no duplicate hai dispatcher.
4. **TODO-P8A-API-1:** POST site/domain/origin chưa có Idempotency-Key lưu bền vững; chưa có PATCH/ETag/If-Match. Endpoint mới có create operations, nên chưa có optimistic update flow.
5. **TODO-P8A-IDOR-1:** service integration assertions đã thêm nhưng chưa thực thi trên DB thật; route-level 404/role behavior cần WSL integration.

## P7 — site/origin, rules và billing (MVP một phần) — 2026-11-25

### Đã xác minh

- Đã đọc `docs/control-plane.md` §5.4–§5.6. Thêm `pkg/netguard`: kiểm tra toàn bộ DNS answer set, từ chối loopback/private/link-local/shared-address/metadata và kiểm tra lại DNS tại thời điểm dial; kết nối bằng IP số đã xác minh để chặn rebinding. Edge `OriginPool.dial` dùng package này, giữ resolver/dialer injection hiện có; tắt `ProxyFromEnvironment` để forward proxy không thể resolve origin hộ và bypass guard. Có unit test public/mixed answer, IPv4-mapped IPv6, giả lập rebinding và assertion transport không dùng env proxy.
- Thêm validator origin (scheme http/https, cổng 80/443/8080/8443, không userinfo, resolve qua `netguard`) và interface DNS với kiểm tra TXT/CNAME theo token hash. Có handler tạo site/thêm domain/thêm origin; service kiểm RBAC/quota, hostname chuẩn hóa + unique constraint hiện hữu, audit trong transaction; migration `00004` thêm trạng thái verification và outbox cấu hình RLS.
- Thêm bước validate DSL bằng `wafcore.Compile`, kiểm tra action/mode, nhập CSV access-list và parse/chuẩn hóa CIDR.
- Thêm interface `PaymentProvider`, `FakeProvider`, và xác minh chữ ký Stripe HMAC/timestamp; không lưu dữ liệu thẻ.
- Lệnh package tests: `go test ./pkg/netguard ./controlplane/internal/site ./controlplane/internal/rules ./controlplane/internal/billing` → PASS. Edge proxy test cục bộ có cả test loopback bị Windows sandbox chặn; xem “Chưa xác minh”.

### Chưa xác minh — lệnh tự chạy lại

- `go test ./edge/internal/proxy -count=1` và `go test -race -count=1 ./...`: lượt này bị Windows sandbox từ chối mở loopback (`connectex ... forbidden`) trong test HTTP/SSE/WebSocket; cần chạy WSL/Linux.
- Migration `00004` và handler DB-backed chưa chạy trên PostgreSQL thật; chạy `DATABASE_URL=... go test -tags=integration -race -count=1 ./controlplane/internal/integration` sau khi thêm integration coverage bên dưới.
- Chưa có Stripe sandbox account/network credentials; chỉ FakeProvider và pure signature verifier đã được test.

### Nợ kỹ thuật (chưa hoàn tất phase)

1. **TODO-P7-SITE-1:** hoàn thiện origin connection probe trong worker cô lập mạng; hiện có validate + rebinding-safe dial package, nhưng handler chưa enqueue/đợi kết quả probe. Thêm E2E Postgres + fake DNS và kiểm thử transition/retry/tranh chấp hostname.
2. **TODO-P7-RULES-1:** custom rule CRUD đầy đủ, rate-limit/access-list/WAF/bot/cache persistence, quota transactionally enforced, conflict/log simulation, history/rollback, ETag/If-Match 409 và Idempotency-Key chưa triển khai; hiện chỉ có validator DSL/CSV.
3. **TODO-P7-BILLING-1:** StripeProvider thật, checkout/portal routes, subscription state machine, webhook persistence/dedup/background worker/reconcile/invoice numbering chưa triển khai; hiện chỉ có interface, fake và verifier.
4. **TODO-P7-OUTBOX-1 (được tách thành TODO-P8A-OUTBOX-1):** outbox được ghi cùng domain verification; API chưa nối NATS và chưa có dispatcher worker marking/retry.
5. **TODO-P7-TEST-1:** chưa có test integration cho webhook trùng/muộn/sai thứ tự, quota vượt gói, concurrent If-Match và E2E Postgres site/domain/origin.

### Kiểm thử lần này

- `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0, không output; `go build ./...` → exit 0, kèm cảnh báo Windows `go: writing stat cache ... Access is denied`.
- `go test ./pkg/netguard ./controlplane/internal/site ./controlplane/internal/rules ./controlplane/internal/billing ./controlplane/internal/api` → PASS; sau chỉnh service, `go test ./controlplane/internal/site ./controlplane/internal/api` cũng PASS. Các test proxy `TestDialUsesResolvedIP`, `TestDialRebindingBlocked`, `TestProxyErrorsCarryRequestIDAndDoNotReflectUnsafeRequestID`, `TestProxyErrorDoesNotLogOrReflectUnsafeRequestID` → PASS.
- `go test -count=1 ./...` → FAIL do môi trường Windows từ chối loopback: `TestLoopbackChallengeVerifyBodyReadDeadline`, nhiều `TestLoopback*` trong `edge/internal/edgecore`, `edge/internal/listener`, `edge/internal/proxy` (`connectex ... forbidden`); các unit package khác gồm netguard, site, rules, billing đều PASS. Không coi full suite là xanh; cần lệnh tự chạy lại bên dưới.
- `go test -race -count=1 ./...` → không chạy được: `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` (máy này không cấu hình CGO).
- Lệnh xác minh trên WSL: `golangci-lint run ./...`; `go vet ./...`; `go build ./...`; `go test -race -count=1 ./...`; `go test -count=1 ./...`; rồi chạy Postgres integration sau khi bổ sung TODO-P7-TEST-1.

## Control Plane — schema, auth, tenant, entitlement — 2026-11-24

### Đã triển khai

- `controlplane/migrations/00001_core.sql`: các bảng ở control-plane.md §4.2 cùng bảng token email/reset/TOTP cần cho auth; UUID do app sinh bằng UUIDv7; site/rule có `deleted_at`; bảng tenant có `tenant_id`, `created_at`, `updated_at`, RLS `ENABLE` + `FORCE`. `waf_api` là `NOBYPASSRLS`; `waf_worker` là role hệ thống tách biệt. Quyền `audit_logs` chỉ INSERT. `WithTenantTx` đặt `SET LOCAL app.tenant_id`; `db.Open` từ chối superuser/BYPASSRLS và login không thuộc `waf_api`.
- `sqlc.yaml`, query mẫu, `make gen` và migration Goose đã thêm. `controlplane/openapi/v1.yaml` có endpoint auth/session/TOTP, tenant member/invitation/API key/entitlement; models sinh bằng oapi-codegen và dùng `Credentials` trong handler.
- Platform có config/env, pgx pool, Redis, NATS, JSON slog với request_id/trace_id, `SecretStore` interface, RFC 9457 problem+json, request ID/recover/CORS/CSRF và Redis API rate limit.
- Auth có đăng ký user + personal org + owner membership + Free subscription + verification token + audit trong một DB transaction; token email/reset băm và hết hạn; Argon2id; lockout account qua Redis; TOTP RFC 6238 lệch ±1, secret AES-GCM mã hóa, 10 recovery code băm dùng một lần; JWT EdDSA 15 phút; refresh rotation/reuse revoke theo family; password reset và quản lý phiên. Login/reset trả lỗi không tiết lộ email tồn tại.
- Tenant có RBAC qua `Can` với test phủ mọi action/role; invitation băm/hạn 7 ngày/accept một lần ràng buộc email; API key scope có metadata/list/revoke và chỉ lộ khóa lúc tạo. Entitlement seed theo quota `data-plane.md` §5.15, có service kiểm quota và usage counters. Mutations liên quan tenant ghi audit trong transaction.
- Integration test gắn `integration`: Postgres RLS bằng login API thực (truy vấn sites không WHERE), IDOR, role grants và audit insert-only; đăng ký/email Mailhog, brute-force Redis, refresh reuse, TOTP ±1. CI integration job có Postgres, Redis, NATS và Mailhog service.

### Đã xác minh

- Kiểm tra cuối sau sửa tenant service và test PoW: `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0, không output; `go build ./...` → exit 0 (Go có in cảnh báo quyền ghi stat-cache Windows, nhưng lệnh kết thúc exit 0).
- `go test -count=1 ./...` → PASS toàn repo, gồm Control Plane và Edge. Lần chạy đầu trong sandbox bị Windows chặn loopback; lần chạy lại ngoài sandbox hoàn tất exit 0, tất cả package có test đều `ok`.
- `go test -tags=integration -run '^$' ./controlplane/internal/integration` → `ok ... [no tests to run]`, xác nhận integration test biên dịch.
- `govulncheck ./...` → `No vulnerabilities found.`
- `go run github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.9.0 -config controlplane/openapi/oapi-codegen.yaml controlplane/openapi/v1.yaml` → exit 0.
- `go run github.com/sqlc-dev/sqlc/cmd/sqlc@v1.30.0 generate -f sqlc.yaml` → exit 0.
- `go mod tidy`, `git diff --check` → exit 0. `govulncheck ./...` → `No vulnerabilities found.`

### Chưa xác minh — lệnh chạy lại trong WSL/Linux

- `go test -race -count=1 ./...` chưa chạy được trên Windows này: output `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` (hiện `CGO_ENABLED=0`). Chạy lại trên WSL/CI Ubuntu.
- Postgres/Redis/Mailhog integration chưa chạy thật tại môi trường này: Docker daemon không mở (`dockerDesktopLinuxEngine` pipe không tồn tại), cổng 5432/6379/1025 không nghe. Lần chạy `go test -tags=integration -count=1 -v ./controlplane/internal/integration` báo SKIP do thiếu `DATABASE_URL` và `REDIS_ADDR`; không tính là xác minh integration. CI job đã cấu hình services nhưng chưa quan sát được kết quả CI trong lượt này.
- WSL local: `docker compose -f deploy/docker-compose.yml up -d --wait postgres redis mailhog`, rồi `DATABASE_URL='postgres://waf:change-me-local@127.0.0.1:5432/waf?sslmode=disable' REDIS_ADDR=127.0.0.1:6379 MAILHOG_ADDR=127.0.0.1:1025 MAILHOG_API_URL=http://127.0.0.1:8025/api/v2/messages go test -tags=integration -race -count=1 -v ./controlplane/internal/integration`. Sau đó chạy `go test -race -count=1 ./...`.

### Nợ kỹ thuật

- **TODO-CP-1:** tích hợp SMTP production có TLS, transactional outbox và retry. Mailhog là adapter dev; nếu SMTP lỗi sau khi commit, tài khoản/token đã lưu nhưng hiện chưa có luồng resend.
- **TODO-CP-2:** provision thông tin đăng nhập riêng cho `waf_api`/`waf_worker` ở deploy/KMS; migration tạo group role NOLOGIN. API startup buộc dùng login không-superuser được grant `waf_api`.
- **TODO-CP-3:** JWT `kid` hiện cố định `cp-1`; key rotation/JWKS, SecretStore production/KMS và cấp TOTP key ở runtime chưa nối.
- **TODO-CP-4:** CI/WSL phải chạy integration thật + `-race` để xác nhận Goose migration, quyền API dưới role `waf_api`, Redis, Mailhog và race. Chưa đóng cho tới khi job đó xanh.
- **TODO-CP-5:** API key issuance/list/revoke đã có; xác thực API key và thực thi scope trên tài nguyên API chưa có trong phạm vi schema/auth/tenant/entitlement lượt này.
- **TODO-CP-6:** bảng tenant chính đã migrate; handlers của site/rule/cert/billing và back-office worker workflows thuộc các module control plane kế tiếp.

## P7-verify — hạn chế lộ dữ liệu xác thực — 2026-11-25

### Đã triển khai

- Migration mới `controlplane/migrations/00002_auth_user_rls.sql`; migration `00001` giữ nguyên. Bật `ENABLE` + `FORCE RLS` cho `users`, `refresh_tokens`, `totp_recovery_codes`, `password_reset_tokens`, `email_verification_tokens`; policy theo `app.user_id`, thiếu GUC trả tập rỗng. `WithTenantTx`, `WithUserTx`, `WithUserTenantTx` dùng `set_config(..., true)`.
- `waf_api` không còn quyền bảng/cột đọc, chèn hoặc sửa password hash, secret TOTP, hash phiên/token, recovery code, API key, invitation hay domain verification. Metadata phiên bị giới hạn theo RLS. Danh sách thành viên trả qua `tenant_list_members`, chỉ gồm ID/email/role/thời điểm tạo.
- Auth và tenant dùng các hàm `SECURITY DEFINER` giới hạn quyền, `search_path=pg_catalog, public`, quan hệ schema-qualified, owner `waf_worker` (NOLOGIN, BYPASSRLS, không phải superuser), và `EXECUTE` bị thu hồi khỏi PUBLIC. Có kiểm tra hash Argon2 giả cho login không tồn tại, timing floor cho reset/registration, hàng đợi email có trần; TOTP dùng step đơn dụng. Trigger ghi audit không kèm bí mật cho mutation của user/session/token/TOTP.
- Integration test tách theo `t.Run`: RLS allowlist có lý do, quyền cột nhạy cảm, session chéo user, hàm definer/search_path, đăng ký/xác minh/reset/logout, API key/invitation, TOTP replay và refresh đồng thời. Job `cp-integration` dùng PostgreSQL 18 + Redis + Mailhog, chạy `-race -count=20`; `CP_INTEGRATION_REQUIRED=1` biến thiếu dịch vụ thành FAIL thay vì SKIP. CI chạy `make gen` rồi `git diff --exit-code`.

### Đã xác minh

- `go test ./controlplane/internal/api ./controlplane/internal/auth ./controlplane/internal/tenant` → PASS.
- `go test -tags=integration -run '^$' ./controlplane/internal/integration` → PASS, code integration biên dịch.
- Trên WSL Ubuntu, với PostgreSQL 18.6 và Redis 8.0.5 thật: Goose migration lên version 2 thành công; `go test -tags=integration -count=1 -v ./controlplane/internal/integration` → PASS, 3 test nhóm/đầy đủ subtest, không SKIP; `go test -tags=integration -race -count=20 ./controlplane/internal/integration` → `ok ... 55.040s` (0 exit). Cấu hình CI dùng cùng `CP_INTEGRATION_REQUIRED=1` để thiếu service là FAIL.
- Trạng thái mới nhất trên Windows/Go 1.26.11: `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0, không output; `go build ./...` → exit 0 (có cảnh báo quyền ghi stat-cache vào module cache Windows, không ảnh hưởng kết quả).
- `make gen` đã chạy thành công: oapi-codegen v2.9.0 và sqlc v1.30.0. Sinh thêm `TotpLastStep` trong `controlplane/internal/dbsqlc/models.go`, đúng với migration 00002.
- `go test -count=1 ./...` trên Windows → FAIL chỉ ở các test loopback thuộc `edge/internal/bot`, `edge/internal/edgecore`, `edge/internal/listener`, `edge/internal/proxy`; output là `connectex ... forbidden by its access permissions`. Các package Control Plane gồm integration-independent tests PASS. Đây là giới hạn loopback của sandbox Windows; không tính là xanh toàn repo.

### Chưa xác minh — lệnh chạy lại trong WSL/PostgreSQL 18

- `go test -race -count=1 ./...` toàn repo chưa xác minh ở phiên cuối: Windows không bật CGO; lần thử WSL bị `Wsl/E_ACCESSDENIED`. Chạy lại trên WSL/CI Ubuntu: `go test -race -count=1 ./...`.
- `go test -race -count=1 ./...` không xác minh được: Windows hiện `CGO_ENABLED=0`, lần gọi WSL bị `Wsl/E_ACCESSDENIED`. Chạy lại ngoài sandbox trên WSL/CI Ubuntu.
- `govulncheck ./...` lần này FAIL trước scan vì DNS/mạng: `fetching vulnerabilities ... lookup vuln.go.dev: no such host`. Lần PASS trước đó là trước thay đổi này; chạy lại khi có mạng.
- `git diff --exit-code` của generate chỉ có ý nghĩa sau khi commit các thay đổi mã nguồn/generated hiện tại.
- **P7-verify chưa đóng:** kiểm chứng tích hợp thật đã xanh, nhưng chưa có GitHub Actions run xanh cho commit hiện tại; không có test nào được tính là đã chạy thật nếu bị SKIP.

### Nợ kỹ thuật

- **TODO-P7V-1:** CI PostgreSQL 18/Redis/Mailhog `cp-integration` phải xanh đủ 20 lượt; đặc biệt xác minh migration Goose, RLS, owner/search_path của SECURITY DEFINER và refresh cạnh tranh. Không đóng khi job lỗi hoặc báo SKIP.
- **TODO-P7V-2:** provisioning production của migration principal có `CREATEROLE` và membership cần thiết để đổi owner sang `waf_worker`, không dùng superuser; credential `waf_api`/`waf_worker` vẫn chưa cấp trong deploy.
- **TODO-P7V-3:** audit trigger ghi mutation của bảng auth nhưng không audit được SELECT tùy ý của một worker login trực tiếp; worker phải dùng entrypoint có audit hoặc triển khai pgAudit trước khi cấp credential.

## P7-close — ràng buộc danh tính tạo refresh — 2026-11-25

### Đã xác minh

- Migration bổ sung `00003_refresh_identity_guard.sql` đã được Goose áp dụng trên PostgreSQL 18.6. `auth_create_refresh` yêu cầu `app.user_id` trùng `p_user_id`, khóa đọc hàng user và chỉ nhận status `active`; tạo session đồng thời ghi `auth.session.create` với tenant lấy từ org cá nhân/default tenant (NULL nếu user chưa có tenant).
- Login chỉ gọi tạo session sau khi lấy login material, xác minh password và TOTP/recovery; thao tác gọi qua `WithUserTx` với ID đã xác minh. Test thực chứng minh user A gọi hàm cho user B và gọi khi thiếu user context đều bị `forbidden`, không thay đổi số session; cấu hình TOTP chéo user trả false; list thành viên tenant B rỗng; ghi key/invitation chéo tenant bị từ chối.
- Test tích hợp kiểm role viewer không tạo key/invitation, admin không mời role owner, scope ngoài allowlist bị từ chối; login hợp lệ tiếp tục tạo refresh và audit. Inventory `SECURITY DEFINER` phải khớp allowlist; test kiểm toàn bộ có `search_path` cố định, owner `waf_worker` không superuser, không EXECUTE cho PUBLIC hay role khác ngoài owner/`waf_api`.
- Output WSL thật, Postgres 18.6 + Redis 8.0.5, `CP_INTEGRATION_REQUIRED=1`: `go test -tags=integration -race -count=20 ./controlplane/internal/integration` → `ok github.com/example/wafplatform/controlplane/internal/integration 64.448s` (exit 0, không SKIP). Lượt verbose đơn cũng PASS: `PASS; ok ... 4.288s`.
- `./scripts/check-controlplane-sql.sh` → `controlplane SQL concatenation check passed`; được thêm vào `make check-cp-sql` và bước CI. Loại bỏ SQL động trong entitlement, thay bằng câu SQL tĩnh theo allowlist quota.

### Chưa xác minh

- GitHub Actions cho commit hiện tại chưa chạy/xanh. `go test -race -count=1 ./...` toàn repo và govulncheck cần chạy lại trên CI/WSL có mạng; lượt trước Windows chặn loopback tests, WSL race toàn repo bị từ chối quyền, govulncheck không resolve `vuln.go.dev`.

### Nợ kỹ thuật

- **TODO-P7C-1:** app session GUC không chống được SQL tùy ý đã thực thi dưới `waf_api`, vì câu SQL đó có thể tự gán `app.user_id`; kiểm tra CI cấm SQL nối chuỗi/dynamic SQL, giữ truy vấn tham số hóa/sqlc, theo dõi audit tạo session và rate-limit/giám sát bất thường. Nâng cấp có chữ ký cho DB identity context là hướng sau này.
- Giữ TODO-P7V-2 (provision migration/API/worker roles production) và TODO-P7V-3 (audit SELECT worker); chưa đánh dấu P7-verify hoàn tất cho tới khi CI `cp-integration` xanh, không SKIP.

## P12 — logging và telemetry

### Đã xác minh

- Thay exporter Prometheus viết tay ở `pipeline` và `/configsync/metrics` bằng adapter `prometheus/client_golang` sau interface `pipeline.Metrics`; chỉ labels hữu hạn, không gắn `site_id`. `/metrics` có histogram từng phase; counter block theo phase/nhóm, rate-limit, log/audit dropped, cache hit, origin error; gauges snapshot version/age/stale, cert expiry, goroutine và heap.
- Log request theo `wafcore.LogEvent`; stats `wafcore.SiteStats1m` tổng hợp trong worker. Security events không lấy mẫu; event thường mặc định Free 1%, Pro 10%, Business 50%, Enterprise 100%. Queue bounded 4096, enqueue không chờ; batch theo 1 giây/1000 record/512 KiB, zstd; gửi NATS hoặc `EDGE_INGEST_URL` HTTPS. IP mặc định mask /24 và /56; không đưa body, Authorization, Cookie hoặc query vào schema/log.
- OpenTelemetry sampler ratio 0.001; OTLP/HTTP exporter được bật bằng `OTEL_EXPORTER_OTLP_ENDPOINT`; W3C trace context được inject tới origin.
- PASS: `go test -count=1 ./edge/internal/telemetry`; `go test -count=1 ./edge/internal/pipeline`; `go test -count=1 ./edge/internal/configsync`; `go test -count=1 ./edge/cmd/edge`; `go test -count=1 -run TestRequestTelemetryUsesWafcoreSchemaAndOmitsSecrets ./edge/internal/edgecore`; `go test -tags=integration -run '^$' ./edge/internal/telemetry` (compile integration test, không gọi NATS).
- **Kiểm tra cuối trên Windows Go 1.26.11:** `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go build ./...` → exit 0 (cảnh báo quyền ghi stat-cache Windows, không ảnh hưởng exit code); `go mod tidy` và `git diff --check` → exit 0. `govulncheck -show verbose ./...` → `No vulnerabilities found.` Trước khi nâng bản vá, scan từng báo 5 vấn đề (2 nhóm module) gồm lỗ hổng bị gọi trong OTel và `x/net`; đã nâng OTel lên v1.47.0, `x/net` lên v0.62.0, `x/crypto` lên bản được DB đánh dấu fixed rồi quét lại sạch.
- **Chưa xác minh trong môi trường này:** `go test -tags=integration -count=1 -v ./edge/internal/telemetry` chạy unit tests xanh nhưng integration FAIL khi kết nối `127.0.0.1:4222`: `connectex: ... socket ... forbidden by its access permissions`; NATS/Docker daemon không chạy và sandbox cấm loopback. Integration build tag biên dịch được và CI đã cấu hình service NATS + Redis, chạy cả hai package với `-race`.
- Toàn repo `go test -count=1 ./...` FAIL ở test loopback bot/edgecore/listener/proxy vì sandbox chặn loopback; không quy lỗi đó cho telemetry. `go test -race` không chạy được tại máy này do `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1` (Windows có CGO_ENABLED=0). Vì vậy phase chưa được xác minh hoàn chỉnh cho tới khi CI Ubuntu/WSL xanh.

### Chưa xác minh — lệnh chạy lại

- WSL/Linux: `go test -race -count=1 ./...`
- Khởi động NATS và Redis local: `docker compose -f deploy/docker-compose.yml up -d nats redis`, rồi `NATS_ADDR=127.0.0.1:4222 REDIS_ADDR=127.0.0.1:6379 make test-integration` (chạy cả Redis và NATS integration với `-race`).
- WSL/Linux/CI Ubuntu cần xác nhận toàn repo và integration thật. Ở môi trường Windows này race dừng trước test vì thiếu cgo; NATS integration không kết nối được do loopback bị chặn. Lint/vet/build/govulncheck và các unit tests liệt kê ở trên đã xác minh.

### Nợ kỹ thuật

- **TODO-P12-1:** pipeline chưa có response cache; metric/cache status hook có sẵn nhưng hit count chưa được nối từ cache implementation.
- **TODO-P12-2:** log shipper best-effort, không có durable local spool/ACK retry; queue/delivery failure được đếm nhưng event bị mất.
- **TODO-P12-3:** NATS integration test mô phỏng mất kết nối bằng TCP proxy với server thật, chưa dừng/restart tiến trình NATS.
- **TODO-P12-4:** trace chỉ được gửi khi OTLP endpoint được cấu hình; không có collector mặc định.
- **TODO-P12-5:** request bytes-in chỉ lấy từ Content-Length; với body chunked giá trị ghi là 0. Stats có thể thiếu khi queue đầy, tương ứng với `log_dropped`.

## P6a — tích hợp edge/control plane (MVP interface) — 2026-11-24

### Đã xác minh

- `CPClient`/`Notifier`/`EmergencyNotifier`/`SnapshotInstaller`/`SecretSink`/`EmergencyActions` tách CP và NATS thành interface; test dùng fake client, không gọi CP thật. `HTTPClient` yêu cầu HTTPS, bootstrap gửi one-time bearer token + CSR, sau đó gọi snapshot/renewal/secrets/heartbeat bằng client certificate mTLS; redirect bị cấm, body response trần 32 MiB.
- `Agent` giữ khóa CSR và identity trong RAM; kiểm tra client cert khớp khóa/CA, gia hạn trước hạn và thay client cert. Snapshot verify Ed25519 theo `kid` → validate wafcore → installer compile/swap → ghi last-good atomic; bad signature/compile giữ bản cũ. LKG production được nạp và xác minh; test outage CP giữ version đang chạy, NATS subscription lỗi vẫn long-poll, heartbeat tiếp tục.
- Secrets/cert site ở `MemorySecrets`; có giới hạn kích thước, store cert theo SNI và token ACME atomic. Emergency command dùng Ed25519 domain-separated signature, expiry ≤5 phút, nonce replay cache có trần và dispatcher chỉ cho ban IP/purge/Under Attack/ACME/drain. `edgecore.SelfTest` chạy request thử qua router và mọi in-process phase; `/readyz` chỉ bật sau self-test. Snapshot age/version/stale xuất ở `/configsync/metrics` và heartbeat.
- Test mới PASS: `go test -count=1 ./edge/internal/configsync` → `ok .../configsync 1.997s`; `go test -count=1 ./edge/cmd/edge` → `ok .../cmd/edge 1.572s`; `go test -count=1 -run TestStartupSelfTestControlsReadiness ./edge/internal/edgecore` → `ok .../edgecore 4.330s`.
- **Đã xác minh trên Windows Go 1.26.11:** `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0, không có output; `go build ./...` → exit 0 (Go in cảnh báo stat-cache Windows `Access is denied`, nhưng exit code 0).

### Chưa xác minh — lệnh chạy lại

- `go test -count=1 ./...` → FAIL do sandbox Windows chặn loopback TCP (`connectex: An attempt was made to access a socket in a way forbidden by its access permissions`); fail ở các test loopback thuộc bot/edgecore/listener/proxy, gồm verify endpoint, self-test proxy/origin, TLS listener, SSE/WebSocket. `TestLoopbackReloadDoesNotInterruptInFlightRequest` không thể bắt đầu origin. Các package configsync, cmd/edge và các package không phụ thuộc loopback đều PASS; suite vẫn đỏ, chưa được đánh dấu hoàn tất.
- `go test -race -count=1 ./...` → chưa chạy: `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`; Windows Go có `CGO_ENABLED=0` và không có gcc. `wsl.exe` tiếp tục bị `Wsl/ERROR_ACCESS_DENIED` trong sandbox.
- Chạy ngoài sandbox trong WSL để xác nhận toàn bộ loopback/race: `golangci-lint run ./...`, `go vet ./...`, `go build ./...`, `go test -race -count=1 ./...`. P9 mới làm contract test với CP/NATS thật; chưa có log CI/CP thật để báo.
- Chưa chạy Redis integration/chaos trên máy này vì WSL không truy cập được: `REDIS_ADDR=127.0.0.1:6379 go test -tags=integration -race -count=5 ./edge/internal/ratelimit`. Đây là lệnh xác minh Redis thật và outage/recovery trong WSL.

### Nợ kỹ thuật P6a / Gate G

- **TODO-P6a-1:** edge identity private key chỉ ở RAM; restart sau khi registration token dùng một lần cần encrypted identity store hoặc bootstrap identity khác. Không ghi private key rõ ra đĩa.
- **TODO-P6a-2:** chưa có NATS adapter thực với mTLS/reconnect; interfaces và fake tests có rồi. Contract test CP/NATS thật thuộc P9.
- **TODO-P6a-3:** emergency verifier/dispatcher có interface nhưng chưa nối vào runtime ban table/cache purge/Under Attack/ACME/drain; ACME token store hiện mới có API bộ nhớ.
- **TODO-P6a-4:** heartbeat hỗ trợ CPU/RAM/RPS/error/p99/log_dropped; app mới điền RAM, các metric host/request cần collector thật.
- **TODO-P6a-5:** self-test chạy router + pipeline phases, chưa chạy TLS và ReverseProxy tới origin.
- **TODO-P6a-6:** chưa chạy chaos matrix end-to-end trong WSL: CP/NATS outage, snapshot sai chữ ký (fake test đã có), Redis outage/recovery thật, clock skew và reload khi có kết nối đang mở. Test reload loopback hiện có nhưng không chạy được trong sandbox Windows.
- **TODO-G-1:** PROXY protocol v2 chưa triển khai.
- Gate G vẫn **chờ xác nhận CI**; các nợ Gate G còn gồm docker compose pull/up, k6 và MMDB thật. TODO-P4f-1 đã đóng theo số liệu Linux do người dùng cung cấp.

## Gate G — đóng nợ nền tảng P2–P5a — 2026-11-24

### Gate G-2 — trạng thái hiện tại

- **Gate G: chờ xác nhận CI** trên commit riêng của lượt G-2. Không coi Gate G hoàn tất trước khi workflow GitHub Actions xanh.
- Host authority: router từ chối cổng 0, authority có userinfo/path/query/control, nhãn >63 byte, hostname >253 byte, trailing dot lặp và punycode lỗi; IPv6 canonical dùng bracket để tính idempotent. Thêm `FuzzNormalizeHost` đối chiếu cấu trúc authority với `url.Parse`/`net.SplitHostPort` và `TestHostAuthorityConsistentAcrossRedirectRoutingAndSNI`.
- Suppression: audit 11 vị trí cũ, bỏ G115 trong `edge/internal/proxy/proxy.go`; còn 10 vị trí G304/G401/G706, mỗi vị trí và test chứng minh được ghi riêng trong `docs/DECISIONS.md`. Không thêm `//nolint` mới.
- Đã chạy trên Windows/Go 1.26.11: `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go build ./...` → exit 0; test mục tiêu `go test -count=1 -run 'TestNormalizeHost|TestHostAuthorityConsistentAcrossRedirectRoutingAndSNI|TestWeightedOriginSelection|TestLoadChallengesReadsConfiguredOperatorFile|TestLoadSnapshotUnsignedJSONDevelopmentFallbackReadsConfiguredFile|TestLoadLocalUsesOperatorPathAndLastKnownGood|TestLoadSignedFileReadsConfiguredOperatorPath' ./edge/internal/router ./edge/internal/listener ./edge/internal/proxy ./edge/cmd/edge ./edge/internal/configsync` → tất cả 5 package PASS; `git diff --check` → exit 0.
- `go test -fuzz=FuzzNormalizeHost -fuzztime=60s ./edge/internal/router` → PASS, 1m1s, 1,219,456 executions, 269 input mới, không panic. Host targeted tests cũng PASS.
- `go test -race -count=1 ./...` chưa chạy được: Go báo `-race requires cgo; enable cgo by setting CGO_ENABLED=1`; `CGO_ENABLED=0`, không có gcc trong Windows PATH. Một lần chạy test package đầy đủ trong Windows sandbox gặp WinSock “access to a socket … forbidden” ở listener/proxy loopback tests. WSL bị từ chối (`wsl.exe` → `Wsl/ERROR_ACCESS_DENIED`), vì vậy cần xác minh lại race và loopback ở WSL ngoài sandbox.
- Nợ đang mở: **TODO-G-1** PROXY v2; `docker compose pull/up`; k6; MMDB thật; **TODO-P4f-2** cooperative fuse không thể interrupt giữa regex/read. CI của Gate G-2 cũng đang chờ xác nhận.

### Đã xác minh

- Line-ending policy: `.gitattributes` buộc LF cho repo và `.go`/`.sh`/`.yml`/`.yaml`/`.md`; `.editorconfig` cũng đặt `end_of_line = lf`. Đã chạy `git add --renormalize .`, sau đó stage riêng config để không gộp code chưa commit; commit riêng `bb6adda chore: enforce LF`. `git ls-files --eol` → `index: no i/crlf files`; `git diff --check` → exit 0. `.gitignore` bỏ qua `.env*` (giữ `.env.example`), file `.mmdb`, `.pem`/`.key`/`.p12`/`.pfx`, thư mục secrets và corpus ngoài.
- Cổng HTTP: `TestHTTPChallengeAndRedirect`, `TestHTTPRedirectRejectsUnknownHost`, `TestHTTPRedirectUsesCanonicalHostAndKeepsPathQuery` trong `edge/internal/listener/listener_test.go`; `TestCanonicalHTTPHostUsesRouterAndRejectsMalformedHosts` trong `edge/internal/edgecore/edge_test.go`. ACME callback vẫn chạy trước canonical host lookup; callback là ranh giới cấp token từ CP. Test kiểm tra unknown/malicious Host, canonical host/path/query và redirect 308. Kiểm tra này tìm ra lỗi thật `known.test:bad` từng bị chuẩn hóa thành `known.test`; `router.NormalizeHost` nay kiểm tra port 1..65535, DNS length, IPv6 bracket, punycode và từ chối authority lỗi; `TestNormalizeHostRejectsMalformedAuthority`/`FuzzNormalizeHost` khóa hành vi.
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
- **TODO-P4f-1** đã đóng theo phép đo Linux/WSL do người dùng cung cấp; benchmark lịch sử p99 >1 giây/work cap tới 100% đã được thay bởi P4f-fix và cổng p99 69 ms.

### Rà soát `//nolint` không-test

- Audit G-2 đã rà từng 11 suppression trước thay đổi: G304 ở main.go (3), configsync/holder.go (4); G401 ở fingerprint.go (2); G115 và G706 ở proxy.go. G115 được gỡ sau khi chuyển counter sang atomic.Int64; còn **10 suppression** (G304 7, G401 2, G706 1), từng lý do/test nêu tại phần Gate G-2 của `docs/DECISIONS.md`. Tests chứng minh đường đọc file cấu hình/operator, vector JA3 độc lập và xử lý request ID; không giữ suppression nếu không có test cụ thể.

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
- Lịch sử P5a: full race từng FAIL ở `TestWAFParallel50GOMAXPROCSMatrix` tại GOMAXPROCS 12 và 2, mỗi lần 1 clean reject/250. Test này được chuyển sang perf job ở P4f-fix; test logic xác định vẫn thuộc race suite.
- `git diff --check` → exit 0; chỉ cảnh báo Git rằng một số working-copy CRLF sẽ được chuẩn hóa LF.

### Chưa xác minh / cần chạy lại

- Lệnh cũ trước P4f-fix (không còn chạy matrix wall-clock trong race suite):

```sh
go test -race -count=1 ./...
go test -tags=perf -count=30 ./edge/internal/waf -run '^TestWAFParallel50GOMAXPROCSMatrix$'
```

- Trên Windows sandbox, loopback bị chặn (WinSock “access to a socket … forbidden”); WSL chạy được qua `/usr/local/go/bin/go` (Go 1.26.11). `wsl.exe -l -q` bị AccessDenied trong sandbox, nhưng lệnh WSL được chạy ngoài sandbox đã PASS cho các test loopback kể trên.

### Nợ kỹ thuật

- **TODO-P5a-1:** PoW replay cache vẫn riêng từng edge; chưa chống replay proof xuyên edge.
- **TODO-P5a-2:** chưa có feed sản xuất cho IP/ASN/Tor hoặc vendor prefix; `IPReputation`/prefix remain operator adapters.
- **TODO-P5a-3:** cấp/rotate HMAC keyring qua mTLS thuộc P6b; hiện keyring operator/env hoặc interface, thiếu key khi entitlement bật là startup error.
- **TODO-P5a-4:** net/http không giữ thứ tự header wire nên tín hiệu thứ tự header chưa được chấm.
- **TODO-P5a-5:** hai raw ClientHello source độc lập đã có; bộ vector vẫn chỉ có hai mẫu, chưa bao phủ rộng nhiều client/phiên bản TLS.
- **P4f status lịch sử:** tải 200 goroutine từng đo p99 1.603 s/work cap 100%. P4f-fix hiện đóng TODO-P4f-1 theo số liệu Linux do người dùng cung cấp; xem mục hiện hành phía trên.
- **Gate G status:** phần code/test được tìm thấy: ACME HTTP-01 trước canonical redirect (`TestHTTPChallengeAndRedirect`), forged XFF bị xóa và IP transport được đặt lại (`TestLoopbackProxyRewritesForwardingHeaders`), `.gitattributes` đặt `eol=lf`. Chưa coi đây là test CI mới độc lập ngoài những test hiện hữu.
- Inventory `//nolint` trong code không-test (11 vị trí; không thêm vị trí mới): `edge/cmd/edge/main.go:207,237,264`; `edge/internal/configsync/holder.go:42,44,79,114`; `edge/internal/listener/fingerprint.go:4,277`; `edge/internal/proxy/proxy.go:138,257`.

## P4f-fix — fuse WAF không từ chối request sạch do scheduler — 2026-11-24

### Đã xác minh

- Gốc lỗi theo code + CI log: `budgetFailure` fail-closed theo wall fuse trước khi biết có anomaly; tier 3 còn áp fail-mode từ fuse ratio lịch sử. CI ghi `active=2`, runnable queue 0, EWMA 28.9 ms, fuse ratio 1.6%, cùng 1 clean reject/250. Đây là nhánh từ chối theo elapsed time, không phải bằng chứng request vượt work cap hay điểm luật.
- Fuse nay là watchdog tối thiểu/mặc định 250 ms, thích ứng theo backlog + EWMA, tối đa 10 s. Khi nổ: giữ điểm đã có, cộng 1 nếu chưa có, gắn `waf_budget_exceeded`, `waf_scan_truncated`, `waf_degraded_fuse`; dưới ngưỡng chỉ allow/log-only, không fail-closed theo tier/fuse ratio. Điểm đã vượt ngưỡng vẫn block; deterministic work cap và body truncation tiếp tục dùng fail-mode.
- Test logic dùng fake clock, fake slow body reader và fake regex delay; tách wall-clock matrix sang build tag `perf`. Log tier throttle toàn tiến trình ≥3 s, tổng thay đổi được đếm.
- PASS cục bộ: `go test -count=1 ./edge/internal/waf` → `ok ... 2.592s`.
- Xác minh Linux/WSL do người dùng cung cấp: `taskset` ma trận GOMAXPROCS 1/2/4 × 50/200 goroutine, 30 lượt/ô; mọi ô clean reject 0, attack bị chặn 100%, fuse 0; p50/request ~135 µs, p99 tổng 0.16–23 ms. Ô xấu nhất 200 goroutine, GOMAXPROCS=4 trên 2 CPU. Tải nền một lõi, 30 lượt: user báo clean reject 0/800.
- Perf job lịch sử đo latency ngay trước `Phase.Handle`; cổng 69 ms sau đó bị loại vì các run GitHub trên 4 CPU cho thấy request-start p99 quá tải dao động dù correctness giữ nguyên. Cơ chế mới được ghi ở mục P4f perf stabilization bên dưới.
- Số đo Windows lịch sử với cổng 69 ms (đã retire): `go test -count=1 ./edge/internal/waf` PASS; perf-tag `-count=30` cũng PASS. 1P/200 goroutine + burner: clean 0/24,000, attacks 6,000/6,000, fuse 0/30,000; p99 1.545–7.431 ms. Ma trận cao nhất p99 62.784 ms ở GOMAXPROCS=2/200 workers; p50 thường 0 theo timer Windows. Đây không thay thế số Linux do người dùng cung cấp.
- Thêm test dưới `-race` cho fuse hết hạn sau URI/query/header/cookie: mỗi loại payload giữ điểm, phần body chưa đọc đánh dấu scan-truncated; test work cap cho 200 params, repeated Aho keywords và JSON lồng sâu chứng minh fail-closed block không gắn wall-fuse tag.

### Chưa xác minh — lệnh chạy lại

- Toàn bộ Linux/taskset số đo hiệu năng được người dùng xác nhận ở trên. WSL trực tiếp từ phiên này vẫn nhận `Wsl/E_ACCESSDENIED`, nên không tự chạy lại hoặc kiểm tra raw logs; CI perf job mới chưa có run URL trong phiên.
- Các lần kiểm tra tổng thể Windows trước đó: lint `0 issues`, vet/build exit 0, govulncheck `No vulnerabilities found`; full `go test ./...` bị sandbox chặn loopback, `go test -race` không chạy do CGO_ENABLED=0. Chúng không thay thế xác nhận CI sau test/priority changes gần nhất.
- CI job bắt buộc perf hiện chạy cả priority/matrix và CPU-background case với `-count=30`; race suite chỉ còn logic xác định. Chưa có trạng thái GitHub Actions sau commit.

### Nợ kỹ thuật

- **TODO-P4f-1: ĐÓNG về correctness**: bất biến kiểm tra mọi lượt, không phụ thuộc latency wall-clock quá tải. Cổng 69 ms là lịch sử và đã bỏ; xem P4f perf stabilization.
- **TODO-P4f-2:** fuse là cooperative checkpoint, không thể ngắt một regex RE2 hoặc `Reader.Read` đang bị treo giữa lời gọi; body socket có deadline riêng, regex chuẩn Go bị giới hạn kích thước đầu vào/RE2. Fake delay test chứng minh policy sau checkpoint, không chứng minh interrupt bất đồng bộ.

## P4f perf stabilization — 2026-11-25

### Đã xác minh

- Nguyên nhân CI chập chờn đã được xác nhận từ log runner 4 CPU cung cấp: cổng wall p99 69 ms đỏ ở 69.88–73.07 ms trong GOMAXPROCS=4/200, trong khi correctness ở các run đó vẫn clean 0/800, attack 200/200, fuse 0/1000. Cổng này đo scheduler/preemption trong ô quá tải; cổng tuyệt đối wall p99 đã bị bỏ ở các ô overload.
- Harness Linux đo thời gian CPU thread cho `Phase.Handle` bằng `getrusage(RUSAGE_THREAD)` trên goroutine ghim OS thread; gate CPU p99 là 10× serial p99 đo ngay trên runner. Ô không quá tải áp median wall p99 ≤5× serial p99. Với ma trận 50/200 goroutine trên runner 4 CPU, wall p99 chỉ ghi nhận/cảnh báo >2× baseline. Tất cả correctness checks vẫn fail ở bất kỳ lượt vi phạm nào; latency được tổng hợp median 30 lượt, không retry.
- Summary gồm p50/p99 mọi ô, runner/OS/nproc/CPU/GOMAXPROCS/goroutine, CPU scan, counters; JSON artifact upload ngay cả khi job đỏ. GitHub actions checkout/setup-go/artifact được nâng lên Node 24.
- Linux/WSL hiện tại (12 CPU/nproc, không phải GitHub 4 CPU), đúng lệnh CI `go test -tags=perf -count=30 -v ./edge/internal/waf -run '^(TestWAFParallel50GOMAXPROCSMatrix|TestWAFCleanFailClosedAtOnePWithCPUBackground)$'` → PASS trong 25.824s. Tất cả 8 ô matrix và case background đều 0 clean reject, 100% attacks, 0 fuse. Summary median p50/p99 và raw JSON 30 lượt được ghi ở `docs/BENCHMARKS.md` và `/tmp/waf-perf-results-final.json` trong WSL.
- Đã xác minh trên WSL: `go vet ./...` exit 0; `go build ./...` exit 0; `go test -race -count=1 ./...` PASS toàn repo. `golangci-lint run ./...` → `0 issues.`.
- `govulncheck ./...` chưa scan được: binary không có trong PATH WSL; thử Windows cũng dừng trước scan do DNS `lookup vuln.go.dev: no such host`. Cần chạy lại khi có mạng.
- Chưa có GitHub Actions run với test harness mới; không đánh dấu job perf runner 4 CPU đã xanh. Lượt user cung cấp trước đó là baseline nguyên nhân, không phải xác minh thay đổi.

### Chưa xác minh — tự chạy trong WSL/Linux

- `go test -tags=perf -count=30 -v ./edge/internal/waf -run '^(TestWAFParallel50GOMAXPROCSMatrix|TestWAFCleanFailClosedAtOnePWithCPUBackground)$'`
- `golangci-lint run ./...`; `go vet ./...`; `go build ./...`; `go test -race -count=1 ./...`; `govulncheck ./...`.
- GitHub perf runner 4 CPU p50/p99 median và uploaded artifact sau thay đổi. WSL không thay được cùng-runner GitHub baseline.

### Nợ kỹ thuật

- TODO-P4f-1 đóng cho đúng correctness và chống scheduler false positive. TODO-P4f-2 vẫn còn: cooperative fuse không thể interrupt giữa lần gọi regex/read; không đổi phạm vi này.

## P4f — ngân sách WAF theo work và suy giảm quá tải — 2026-11-24 (kết quả trước P4f-fix)

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

- **TODO-P4f-1 (historical, closed by P4f-fix):** benchmark tải 50/200 goroutine trước đó cho p99 >1 giây, work cap chạm tối đa 100%, fuse tới 9%. Kết quả Linux/WSL, 30-lượt perf matrix và tolerance hiện hành được ghi ở mục P4f-fix.
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

## P8a-fix — repeatable CP integration and proxy test seam

- Đã rà toàn bộ `controlplane/internal/integration`: hiện chỉ có `core_integration_test.go`. Mọi test tạo identity/email đều đăng ký cleanup; cleanup xóa row theo tenant/user và Redis login-throttle key. Tenant/site/domain/hostname fixtures có ID ngẫu nhiên, suite không cần database rỗng.
- CI CP chạy `go test -tags=integration -race -count=20` trên cùng PostgreSQL/Redis service, không dọn DB giữa lượt; thêm bước 100 lượt cho race hai tenant cùng claim hostname.
- Hostname chuẩn hóa IDNA (U-label/punycode, hoa/thường, dấu chấm cuối); test kiểm cùng một khóa và lỗi unique ngoài `domains_hostname_key` không bị biến thành conflict. Test giữ cuộc đua quota và hai tenant thêm cùng hostname, phản hồi conflict không tiết lộ tenant.
- Proxy test cấp DNS `origin.test → 203.0.113.4` và dialer riêng của test ánh xạ IP đã qua guard tới httptest listener. Test mặc định kiểm từ chối loopback/private/metadata/CGNAT/ULA; không thay đổi netguard.
- **Đã xác minh trên Windows:** `go test ./controlplane/internal/site` PASS; integration package biên dịch với `go test -tags=integration -run '^$' ./controlplane/internal/integration` PASS; `go vet ./...` PASS; `go build ./...` PASS. `golangci-lint run ./...` đầu tiên phát hiện một `ineffassign` vừa thêm, đã sửa và cần chạy lại.
- **Chưa xác minh:** `go test -race -count=1 ./...` không chạy vì `CGO_ENABLED=0`; `wsl.exe --list --verbose` trả `Wsl/E_ACCESSDENIED`; Docker daemon không có pipe; PostgreSQL/Redis service không lắng nghe. `go test ./edge/internal/proxy` bị sandbox Windows chặn loopback và báo 502/`connectex`; chưa thể xác minh test loopback đã sửa trên Linux. Chưa chạy CP integration với `CP_INTEGRATION_REQUIRED=1`.
- Lệnh cần chạy trong WSL/Ubuntu, cùng DB không dọn giữa lượt: `golangci-lint run ./...`; `go vet ./...`; `go build ./...`; `go test -race -count=1 ./...`; `CP_INTEGRATION_REQUIRED=1 go test -tags=integration -race -count=20 ./controlplane/internal/integration`; `govulncheck ./...`; `bash scripts/check-controlplane-sql.sh`.
- **TODO-P8A-FIX-1:** chờ xác minh Linux/WSL và Postgres/Redis thật trước khi đóng; ghi lại output của từng lệnh và xử lý mọi lỗi đỏ.

## P8a-fix-2 — fixture cleanup and generated source check

- Đã sửa cleanup để chạy trong một transaction quản trị; từng câu SQL có danh sách argument riêng, theo thứ tự FK, có savepoint để tiếp tục sau lỗi, và gom lỗi kèm SQL thay vì dừng ở câu đầu. Cleanup role login tạm giờ báo lỗi revoke/drop.
- Thêm integration test seed user/org/site/domain/origin/outbox/session/reset/API key/invitation rồi cleanup và kiểm tra không còn row theo user/tenant trên các bảng public có `tenant_id`, `user_id`, `actor_id`, `created_by`.
- Thêm test schema coverage: mọi bảng public phải được cleanup hoặc nằm trong global allowlist có lý do; mọi bảng mới có khóa fixture mà chưa có coverage làm test đỏ.
- Thêm `make check-generated`; CI gọi chung target này cho gofmt, tidy, sqlc/OpenAPI generation và diff. `AGENTS.md` yêu cầu cập nhật generated sources cùng migration/query/OpenAPI trong cùng commit.
- **Chưa xác minh trên Linux:** WSL launch trả `Wsl/E_ACCESSDENIED`; Docker engine và PostgreSQL/Redis không sẵn có. Chưa chạy fixture trên Postgres thật, `make check-generated` trên Linux, hai lượt `-count=20` trên DB giữ nguyên, hoặc đếm bảng sau chạy.
- **TODO-P8A-FIX-2:** chờ output Linux/WSL của `make check-generated`, hai CP integration run liên tiếp, và query đếm `domains/sites/users/organizations`; không đóng phase trước khi tất cả xanh và số hàng không tăng.
- **Kết quả thực tế lượt này (Windows sandbox, không thay thế Linux):** `golangci-lint run ./...` → `0 issues`; `go vet ./...` → exit 0; `go build ./...` → exit 0 nhưng Go báo không ghi được module stat cache; integration compile `go test -tags=integration -run '^$' ...` và `go test ./controlplane/internal/site` → PASS; `gofmt -l` trên tracked/untracked Go files → rỗng; `go mod tidy` → exit 0. `go test -race` và hai CP `-race -count=20` chạy thử đều dừng trước tests vì CGO tắt. CP non-race required run lặp 20 lần fail-fast do thiếu `DATABASE_URL`/`REDIS_ADDR` (không kết nối DB). `make check-generated` không khởi chạy vì không cài `make`; hai generator `go run ...@version` không tải được module do DNS tới `proxy.golang.org`; `govulncheck` không phân giải `vuln.go.dev`; Bash SQL checker trả `Bash/E_ACCESSDENIED`. WSL trả `Wsl/E_ACCESSDENIED`; không có listener Postgres/Redis để đếm dữ liệu.

## P8a-fix-3 — audit-trigger cleanup ordering

- Cleanup xóa token/recovery/session tables trước, xóa user `default_tenant_id` trước (để trigger user không sinh audit có tenant), xóa `audit_logs` ngay trước `organizations`, rồi xóa users. Planner có test với một cleanup statement giả cho bảng audit-trigger mới nằm sau audit query ban đầu; planner vẫn đẩy audit deletion xuống trước org.
- Fixture test chạy hai lần dọn và kiểm tra dưới PostgreSQL superuser và role `BYPASSRLS` không-superuser, gồm dữ liệu recovery codes, refresh/reset/email tokens, audit, outbox/site/domain. Test cuối `TestZZIntegrationFixtureResidueBudget` nhận diện và dọn fixture legacy theo email prefix kiểm thử, sau đó log/fail nếu users/organizations/sites/domains/audit_logs vượt 5 hàng.
- CI CP hiện log role/`rolsuper`/version, chạy `-count=20` hai lần liên tục trên cùng service DB, chạy hostname race 100 lượt, rồi chạy test đếm residue. Mọi bước đều là required.
- **TODO-CP-3:** chính sách retention/erasure và audit tổng hợp đã ghi trong DECISIONS; worker erasure theo lô và cơ chế không phát per-row auth delete events chưa được triển khai.
- **Chưa xác minh Linux/Postgres trong session này:** WSL và Docker vẫn không truy cập được. Cần chạy lại cả hai job integration 20 lượt liên tiếp và lấy output từ CI/WSL trước khi đóng phase.
- CI có test bước thông tin DB và `TestZZIntegrationFixtureResidueBudget`; lần cuối log tổng số users/organizations/sites/domains/audit_logs và fail nếu bảng nào còn dòng. Tất cả count20 job đều fail-fast nếu bất kỳ test/cleanup lỗi nào.
- **Output thật Windows sandbox lượt này:** `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go build ./...` → exit 0 (Go in cảnh báo không ghi được module stat cache do Access denied); `go vet -tags=integration ./controlplane/internal/integration` → exit 0; `go test -tags=integration -run '^(TestAuditCleanupPlannerDefersAuditAfterNewTriggerTable|TestIntegrationCleanupRemovesFixtureRows|TestZZIntegrationFixtureResidueBudget)$' ./controlplane/internal/integration` → `ok ... 0.161s` (DB-dependent tests tự Skip vì không có DATABASE_URL); `git diff --check` → sạch. `go test -race -count=1 ./...` và hai lượt integration `-race -count=20` → `go: -race requires cgo; enable cgo by setting CGO_ENABLED=1`. Integration non-race `-count=20` → FAIL mọi DB test do `connectex` tới `127.0.0.1:5432`; `Test-NetConnection` trả `False`. `wsl.exe --list --verbose` → `Wsl/E_ACCESSDENIED`; `make check-generated` → `make is not recognized`; `govulncheck ./...` → DNS lookup `vuln.go.dev` thất bại; `bash scripts/check-controlplane-sql.sh` → `Bash/E_ACCESSDENIED`.

## P8a-fix-4 — site status check in hostname race

- Root cause in the failing assertion: the test ran `AddDomain` concurrently for tenant A's site and tenant B's site, but always queried tenant A's site after verifying the one winning domain. Either site can win the globally unique hostname; only the winning site's status should become active. Production's domain and site transition behavior matches docs/control-plane.md 5.5.
- Test now records each request's site ID, checks both sites remain `pending_dns` after creation/domain/origin, expects the DNS-verified winner to be `active` and loser to remain `pending_dns`, and checks expiry marks the domain failed without changing its site's status. No production code or hostname conflict invariant changed.
- User reported CP integration fails in two WSL/CI runs and residue counts zero after commit `6769015`. This session cannot independently retrieve run logs: `gh` is not installed and outbound DNS to `api.github.com` fails. Workflow jobs are lint, test-race, perf, govulncheck, compose, and cp-integration; only cp-integration failure is reported in the supplied evidence, other job conclusions remain unverified.
- **Unverified:** no local PostgreSQL/Linux/WSL or race-capable CGO. Re-run targeted same-hostname race `-count=100 -race`, full suite, and CP integration twice on the same database in WSL/CI; inspect all workflow job conclusions before closing.
- **Output thật bổ sung (Windows sandbox):** `golangci-lint run ./...` → `0 issues.`; `go vet ./...` → exit 0; `go build ./...` → exit 0; integration package compile `go test -tags=integration -run '^$' ...` → PASS; planner test → PASS. Integration test `-v`/residue budget → không tới assertions vì kết nối PostgreSQL bị Windows sandbox chặn (`connectex`, `127.0.0.1:5432`). `go test -race -count=1 ./...`, targeted `-race -count=100`, CP `-race -count=20` hai lần → dừng trước test do `CGO_ENABLED=0`. `make check-generated` → make chưa cài; `govulncheck ./...` → DNS `vuln.go.dev` không phân giải; SQL checker → `Bash/E_ACCESSDENIED`; truy vấn GitHub Actions → `api.github.com` DNS không phân giải, `gh` chưa cài.

## P8b — snapshot publisher/distribution MVP

- **Đã triển khai:** worker polling transactional outbox dùng `FOR UPDATE SKIP LOCKED` rồi phát NATS `config.changed`; debounce 3 giây, tải cấu hình trong PostgreSQL Repeatable Read, giới hạn entitlement và compile rule DSL bằng `wafcore`; lỗi theo site giữ cấu hình cũ/cảnh báo. Version toàn cục có sequence migration `00005`; snapshot checksum SHA-256, Ed25519 qua interface SecretStore, metadata latest/retention 50; GET internal snapshot dùng mTLS, edge-id + certificate serial, since/ETag/304; publish `config.updated`. Outbox có ngữ nghĩa at-least-once.
- **Đã kiểm tra cục bộ:** có unit test entitlement/isolation, mTLS endpoint semantics/debounce và contract test tạo snapshot ký rồi nạp vào `edgecore` thật, self-test và `wafcore.LogEvent` serialization. Contract test ghi elapsed khi chạy `-v`.
- **Chưa xác minh:** migration/Postgres thật, NATS, worker TLS và hợp đồng edge qua network; `edge/internal/edgecore` tests cần loopback mà Windows sandbox chặn. Chưa có output Linux đo rule-save→edge-apply. Chạy lại trong WSL: `go test -v ./controlplane/internal/snapshot ./edge/internal/edgecore`; `go test -race -count=1 ./...`; migration `make migrate` trên DB dev; worker với NATS/Postgres/mTLS cấu hình.
- **Nợ kỹ thuật:** TODO-P9A-1 S3-compatible store + production SecretStore; TODO-P9A-2 site region placement; TODO-P9A-3 canary/heartbeat stop + rollback; TODO-P9A-4 per-edge secret envelope + enrollment + signed nonce emergency channel; TODO-P9A-5 chaos/network contract tests, run migration trên DB thật và đo save-to-apply trên Linux. Xem chi tiết trong `docs/DECISIONS.md`.
- **Output thật trong lượt này (Windows sandbox):** `golangci-lint run ./...` → `0 issues`; `go vet ./...` → exit 0; `go build ./...` → exit 0; targeted CP/API/snapshot/configsync package tests → PASS; integration package compile `go test -tags=integration -run '^$' ./controlplane/internal/integration` → PASS, tests not run; contract `go test -v ./edge/internal/edgecore -run '^TestControlPlaneSnapshotLoadsIntoRealEdge$' -count=1` → PASS, các lần đo build→apply 6.4556 ms, 7.1717 ms, 6.679 ms trên Windows (mẫu test cục bộ nhỏ, không phải benchmark Linux); `go test -count=1 ./...` → FAIL ở loopback tests do Windows sandbox `connectex`/forbidden socket. `go test -race -count=1 ./...` không khởi chạy (`CGO_ENABLED=0`, race requires CGO); `govulncheck ./...` không lấy được database do DNS `vuln.go.dev` không resolve. `git diff --check` → sạch.

## P9a-verify — snapshot/outbox integration coverage

- **Đã thay đổi:** thêm CP integration test build-tag `integration` cho domain/site → outbox → NATS `config.changed` → snapshot builder → checksum/Ed25519 kid/entitlement trim/secret scan → NATS `config.updated` → endpoint mTLS qua TLS server và test CA tự sinh; có ETag, since, invalid input và log elapsed từ trước build đến sau nhận response edge. Job `cp-integration` có service NATS và `NATS_URL`.
- **Đã thay đổi:** endpoint còn kiểm tra CN/DNS SAN/URI SAN của cert client khớp edge ID đã đăng ký; edge serial vẫn phải được lookup ở trạng thái active/ready. Edge configsync tuần tự hóa apply và từ chối version thấp/equal; có test chấp nhận rollback content dưới version mới, từ chối replay thấp và kid lạ.
- **Đã chạy thật trên Windows:** `go test ./controlplane/internal/snapshot ./edge/internal/configsync` → PASS; `go test -tags=integration -run '^$' ./controlplane/internal/integration` → PASS (chỉ compile, không chạy integration). Trước đó lần đầu compile test replay phát hiện biến không dùng; đã sửa rồi chạy lại thành công.
- **Đã xác minh cục bộ (Windows):** `golangci-lint run ./...` → `0 issues`; `go vet ./...` → exit 0; `go build ./...` → exit 0 (Go có cảnh báo không ghi stat cache vào `%GOMODCACHE%`, nhưng build thành công); `go test ./controlplane/internal/snapshot ./edge/internal/configsync` → PASS; `go test -tags=integration -run '^$' ./controlplane/internal/integration` → PASS, compile-only; `git diff --check` → sạch; quét toàn repo xác nhận không còn nhãn TODO thuộc P8B. `go test -count=1 ./...` → FAIL chỉ ở các test cần loopback của bot/edgecore/listener/proxy do Windows sandbox từ chối kết nối `127.0.0.1` (`connectex`); các package khác PASS.
- **Chưa xác minh:** PostgreSQL/NATS integration thật; lệnh required `CP_INTEGRATION_REQUIRED=1 go test -tags=integration -run '^TestSnapshotOutboxNATSSigningAndMTLSEndpointIntegration$' ...` FAIL ngay với thông báo cần `DATABASE_URL` và `REDIS_ADDR`; hai lượt `-race -count=20` không khởi chạy vì `CGO_ENABLED=0`; full race cũng không chạy được vì cùng lý do. Không có Linux/Postgres/NATS/CI output hoặc latency Linux. `make check-generated` không chạy vì `make` chưa cài; `govulncheck ./...` không tải được DB do DNS `vuln.go.dev` không phân giải; `bash scripts/check-controlplane-sql.sh` bị `Bash/E_ACCESSDENIED`. Không tuyên bố P9a đã xác minh hoàn tất.
- **Nợ kỹ thuật:** TODO-P9A-1 S3-compatible object storage/production SecretStore; TODO-P9A-2 region placement; TODO-P9A-3 canary/rollback orchestration; TODO-P9A-4 per-edge secret envelope/enrollment/emergency channel; TODO-P9A-5 Linux/real-service repeated integration, chaos, network edge contract và latency; TODO-P9A-6 outbox publish có thể lặp nếu crash sau NATS publish trước DB commit (at-least-once, cần JetStream dedupe hoặc consumer idempotency evidence).

## P9a-fix-1 — snapshot fixture mode và cảnh báo PostgreSQL

- **Nguyên nhân gốc xác định:** lỗi `snapshot entitlement trim site=<nil>` là tất định, không phụ thuộc race/thời gian. Schema DB định nghĩa `rules.mode` là `enforce` hoặc `log`; loader đưa thẳng `enforce` vào `wafcore.Rule.Mode`, trong khi hợp đồng snapshot xem mode rỗng là enforce mặc định và chỉ chấp nhận giá trị tường minh `log`. `Snapshot.Validate` vì vậy loại site khỏi snapshot. Khi builder ghi cảnh báo cho site lỗi, `WarnSite` truyền `$3` chưa định kiểu vào `jsonb_build_object` (hàm polymorphic), nên PostgreSQL trả SQLSTATE 42P18 `could not determine data type of parameter $3`.
- **Sửa:** loader ánh xạ DB `enforce` thành mode rỗng của wafcore, giữ `log`; SQL cảnh báo cast `$3::text`. Integration assertion yêu cầu site fixture không bị cảnh báo/loại khỏi snapshot và các rule enforce được serialize thành mode mặc định. Có unit test cho mapping mode.
- **Môi trường:** WSL và CI được cung cấp cùng lỗi, nên không có bằng chứng khác biệt có ảnh hưởng. CI có NATS service và `NATS_URL=nats://127.0.0.1:4222`; WSL chạy NATS JetStream và test mặc định cùng URL local. Lỗi xảy ra khi build/validate snapshot, trước endpoint; không phải timeout, NATS hay scheduling. WSL log cho thấy lỗi trong cả lượt đơn và `-count=20`; user báo 20/20 lần fail, residue sau chạy bằng 0.
- **Đã xác minh trong phiên này (Windows):** `golangci-lint run ./...` → `0 issues`; `go vet ./...` → exit 0; `go build ./...` → exit 0 (Go cảnh báo không ghi stat cache nhưng build thành công); `go test ./controlplane/internal/snapshot` → PASS; integration compile `go test -tags=integration -run '^$' ./controlplane/internal/integration` → PASS (test không thực thi); `gofmt -l` trên các file đã sửa → rỗng. Required integration chạy không race với `CP_INTEGRATION_REQUIRED=1` → FAIL-fast vì môi trường không đặt `DATABASE_URL`/`REDIS_ADDR`; hai lệnh race dừng trước test vì CGO tắt. WSL trả `Wsl/E_ACCESSDENIED`; không có kết quả tích hợp sau fix trong phiên này.
- **Chưa xác minh / lệnh WSL:** chạy `CP_INTEGRATION_REQUIRED=1 go test -tags=integration -race -count=20 ./controlplane/...` hai lần liên tiếp trên cùng DB, kiểm tra residue `users/sites/config_snapshots/config_change_outbox=0`; sau đó lint, vet, build, race full repo, generated, govulncheck và SQL guard. Kết quả người dùng cung cấp cho commit `7688803` là lint/build/vet/race/generated/vuln/SQL xanh, nhưng không phải kết quả sau fix này.

## P9a-fix-2 — fixture entitlement và test cảnh báo/mTLS

- **Nguyên nhân gốc theo log WSL/CI:** builder đã dựng, ký và xác minh snapshot. Test fixture dùng subscription Free (seed `bot: none`) nhưng lại yêu cầu `ChallengeHMACKeyID` còn giá trị. `applyEntitlementCaps` chủ ý xóa key reference khi không được entitlement JS challenge; log cho thấy trường này rỗng, trong khi OriginCredentialIDs và Additional vẫn là reference. Đây là assertion/fixture không khớp gói, không phải lỗi chữ ký, mTLS, NATS, worker quyền hay race. CI và WSL đều có NATS và cùng URL local; lỗi xảy ra trước phần endpoint. Không có dấu hiệu timeout.
- **Sửa test, giữ nguyên assertion bảo mật:** chuyển fixture sang Pro (entitlement JS challenge), tăng dữ liệu vượt quota lên 22 rules/6 rate policies, giữ kỳ vọng 20/5 và giữ assertion HMAC reference + scan cấm secret dạng rõ. Thêm unit test xác nhận Free loại challenge reference, Pro giữ reference.
- **Độ phủ bổ sung:** integration test thật cho site lỗi compile, rule mode sai, origin URL sai; lặp builder hai lần và kiểm tra fallback last-good, site tốt không bị ảnh hưởng, mỗi site hỏng chỉ có một alert đúng tenant/site, alert không chứa secret reference, và lỗi ghi alert không làm hỏng build toàn vùng. Test mTLS kiểm cert serverAuth/SAN, edge clientAuth/SAN; serial không đăng ký, serial revoked, cert hết hạn, edge ID query sai, CN/SAN sai và không cert đều bị từ chối.
- **Đã xác minh cục bộ (Windows):** `golangci-lint run ./...` → `0 issues`; `go vet ./...` → exit 0; `go build ./...` → exit 0 (Go cảnh báo stat cache Access denied); `go test ./controlplane/internal/snapshot` → PASS; integration compile `go test -tags=integration -run '^$' ./controlplane/internal/integration` → PASS. `CP_INTEGRATION_REQUIRED=1 go test -tags=integration -run '^TestSnapshotOutboxNATSSigningAndMTLSEndpointIntegration$' -count=1 ...` → FAIL-fast vì thiếu `DATABASE_URL`/`REDIS_ADDR`; `go test -race` và integration `-race -count=20` không chạy do CGO tắt. `make check-generated` không chạy vì thiếu make; govulncheck không resolve DNS `vuln.go.dev`; SQL guard bị `Bash/E_ACCESSDENIED`; WSL bị `Wsl/E_ACCESSDENIED`. Chưa chạy Postgres/NATS thật sau sửa.
- **Chưa xác minh:** hai lượt CP integration `-race -count=20` trên cùng DB và residue 0; full race sau sửa; CI GitHub sau commit. Cần chạy lại trong WSL: hai lần `CP_INTEGRATION_REQUIRED=1 go test -tags=integration -race -count=20 ./controlplane/...`, sau đó kiểm tra dư liệu và các cổng generated/vuln/SQL. Không đánh dấu P9a-fix-2 hoàn tất trước output Linux/CI xanh.
## P8-fix-5 — integration subtest isolation

- Root cause: CI dùng `-run '^TestSiteQuotaHostnameOwnershipAndStateIntegration/same_hostname_race_and_non_disclosing_conflict$'`. Go gọi test cha nhưng lọc subtest quota; phần thân cha vẫn chạy tiếp và truy vấn site mà subtest quota lẽ ra tạo. Truy vấn tại dòng cũ 1736 nhận `pgx.ErrNoRows`, khớp log CI.
- Site integration test có ba subtest độc lập; mỗi subtest tự tạo user/tenant/site bằng UUID/email/hostname ngẫu nhiên và đăng ký cleanup. Hostname race tự tạo hai tenant, hai site và origin. CI chạy parent với `-count=100`, rồi chạy từng subtest bằng filter riêng. Hai lần full integration package `-count=20` vẫn dùng cùng DB không dọn.
- Rà soát subtests khác: cleanup mode seed fixture bên trong mỗi subtest; auth flows seed tài khoản trong mỗi subtest; nhóm credential/identity đã gộp block assertions vào test body vì chúng dùng chung fixture cha. Không bỏ assertion. Residue gate yêu cầu đúng 0 ở users/organizations/audit_logs/sites/domains.
- **Đã xác minh cục bộ:** `golangci-lint run --build-tags=integration ./controlplane/internal/integration` → `0 issues`; `go vet -tags=integration ./controlplane/internal/integration` → exit 0; `go build ./...` → exit 0; integration package compile `go test -tags=integration -run '^$' ./controlplane/internal/integration` → PASS. Filter hostname riêng với verbose chạy đúng parent/subtest rồi SKIP do thiếu DB; với `CP_INTEGRATION_REQUIRED=1` fail đúng vì thiếu `DATABASE_URL`/`REDIS_ADDR`. `go test -race` không khởi chạy vì CGO tắt. Full-repo lint/vet bị typecheck fail do file có sẵn từ thay đổi ngoài scope `edge/internal/edgecore/snapshot_contract_test.go` import package local không tồn tại `controlplane/snapshot`; không sửa/xóa thay đổi đó trong lượt này.
- **Chưa xác minh:** không có Linux/Postgres/Redis/Mailhog hoặc output GitHub Actions. `git pull` bị sandbox chặn ghi `.git/FETCH_HEAD`; HEAD cục bộ `be8f51d` trên `main`, `origin/main` không đổi theo status. Chạy lại trên Linux: hai lượt full integration `-count=20`, parent hostname `-count=100`, ba subtest riêng, residue gate và các lệnh lint/vet/build/race/generated/vuln/SQL trong yêu cầu. Không tuyên bố CI xanh.
