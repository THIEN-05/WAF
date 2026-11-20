# AGENTS.md

## Dự án
Nền tảng bảo vệ website kiểu WAF/CDN-lite gồm 2 phần:
- **Data plane (edge)**: reverse proxy Go, pipeline lọc L7 (access → ratelimit → rules → WAF → bot → cache → proxy).
- **Control plane (CP)**: API, dashboard, billing, snapshot có chữ ký, quản lý edge, ingest log.
Nguồn sự thật thiết kế: `docs/data-plane.md` và `docs/control-plane.md`. Khi mâu thuẫn, mục 2.3 của control-plane.md (hợp đồng CP↔edge) thắng. Nếu thiếu thông tin, chọn mặc định hợp lý, ghi vào `docs/DECISIONS.md`, KHÔNG dừng lại hỏi.

## Quyết định đã chốt (MVP)
- Go 1.22+, một Go module gốc `github.com/example/wafplatform` (đổi sau).
- Dùng chung `pkg/wafcore` (DSL, schema snapshot, schema log, ký/verify Ed25519) giữa edge và CP.
- Edge: net/http + httputil.ReverseProxy tùy biến Transport. Chỉ regexp chuẩn của Go (RE2).
- CP: chi router, pgx + sqlc, goose migration, Postgres, Redis, NATS, ClickHouse, MinIO (S3), River hoặc goroutine scheduler đơn giản.
- Auth tự làm (argon2id, JWT EdDSA 15 phút, refresh xoay vòng). Thanh toán: Stripe test mode, qua interface `PaymentProvider` (có `FakeProvider` cho test).
- KMS/Secrets: viết interface `SecretStore`, bản dev dùng file/env mã hóa, bản prod để sau (AWS).
- Dashboard: Next.js + TypeScript + Tailwind + TanStack Query + Recharts, vi/en.
- Chỉ L7. L3/L4 DDoS ngoài phạm vi.

## Cấu trúc repo
pkg/wafcore/ # DSL, snapshot schema, log schema, sign/verify edge/cmd/edge, edge/internal/{listener,router,reqctx,access,ratelimit,rules,waf,bot,ddos,cache,proxy,response,telemetry,configsync,certs} edge/rulesets/ # managed rules YAML controlplane/cmd/{api,worker,ingest}, controlplane/internal/{auth,tenant,billing,site,rules,certs,snapshot,fleet,analytics,notify,admin,platform} controlplane/migrations/ controlplane/openapi/ web/ # Next.js dashboard deploy/ # docker-compose.yml, Dockerfiles, terraform/ test/ # integration, contract, attack corpus, clean corpus, bench docs/


## Quy tắc code
1. Mỗi phase kết thúc với `make lint test` xanh (golangci-lint, `go test -race ./...`). Viết test cùng lúc với code, không để sau.
2. Edge KHÔNG gọi DB/CP trên đường xử lý request. Config là snapshot bất biến, hoán đổi bằng `atomic.Pointer`. Lấy snapshot 1 lần mỗi request.
3. Rẻ trước, đắt sau; mọi Decision phải có RuleID, Phase, Score, Reason.
4. Mọi tài nguyên có giới hạn: header, body, số rule, kích thước regex, số key bộ đếm, ngân sách thời gian WAF.
5. Log bất đồng bộ, kênh đầy thì bỏ và tăng `log_dropped`; không bao giờ chặn request. Không log body, Authorization, Cookie; redact password/token.
6. Mọi truy vấn DB của tenant phải có `tenant_id`; bật Row-Level Security; API dùng role DB không bypass RLS. Có test IDOR.
7. Bí mật không nằm trong log, không commit. Dùng env + `.env.example`.
8. Idempotent: webhook, job, publish snapshot.
9. Module chỉ gọi nhau qua interface Go; không query bảng của module khác.
10. Ghim phiên bản dependency (go.mod/go.sum, package-lock). Tên thư viện trong docs chỉ là đề xuất.
11. Chỉ viết payload tấn công mẫu ở mức tối thiểu trong `test/corpus` để kiểm thử WAF của chính dự án; không thêm công cụ tấn công.
12. Commit nhỏ, message dạng `phase-N: nội dung`. Cập nhật `docs/PROGRESS.md` cuối mỗi phase (làm xong gì, còn nợ gì, số đo benchmark thực).
13. Không bịa số liệu hiệu năng; chỉ ghi số đo được.
14. Khi một yêu cầu quá lớn, làm bản MVP chạy được trước và ghi TODO có đánh số vào `docs/PROGRESS.md`.

## Lệnh chuẩn (Makefile)
`make up` (docker compose dev), `make down`, `make test`, `make lint`, `make bench`, `make gen` (sqlc, oapi-codegen), `make migrate`.