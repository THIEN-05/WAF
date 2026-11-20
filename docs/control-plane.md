# **Tài liệu kỹ thuật Control Plane**

# **0\. Cách đọc tài liệu**

Control plane là mọi thứ **nằm ngoài đường xử lý request**: dashboard, API, đăng ký/đăng nhập, quản lý website và rule, thanh toán, báo cáo, và việc phát cấu hình cho các edge node. Tài liệu bám theo bản idea của nhóm và khớp với Tài liệu kỹ thuật Data Plane (bản 1.1); các điểm giao tiếp giữa hai bên nằm ở mục 2.3.

Mỗi module viết theo khuôn: **mục đích → luồng xử lý → dữ liệu → chế độ lỗi → kiểm thử**. Lưu ý: tên thư viện chỉ là đề xuất (khi code hãy ghim phiên bản và kiểm tra giấy phép), mọi con số hiệu năng là mục tiêu cần tự đo lại.

# **1\. Mục tiêu, phạm vi và nguyên tắc**

## ***1.1 Control plane làm gì***

Khách hàng (doanh nghiệp hoặc cá nhân) đăng ký tài khoản, mua gói, thêm website, chỉnh rule và xem báo cáo. Control plane lưu mọi cấu hình, kiểm tra tính hợp lệ, đóng gói thành **snapshot có chữ ký** rồi phân phối cho edge. Edge chạy độc lập bằng snapshot nên **control plane gặp sự cố không làm website khách ngừng được bảo vệ**.

## ***1.2 Yêu cầu chức năng***

* FR-C1: Đăng ký, đăng nhập, xác minh email, đặt lại mật khẩu, 2FA (TOTP).  
* FR-C2: Tổ chức (tenant), thành viên, phân quyền RBAC (owner, admin, viewer), API key.  
* FR-C3: Danh mục gói (Free, Pro, Business, Enterprise), entitlement, quota và đo mức dùng.  
* FR-C4: Thanh toán, đăng ký gói, nâng/hạ gói, hóa đơn (Stripe, và VNPay/MoMo/PayOS cho thị trường Việt Nam).  
* FR-C5: Quản lý website: thêm tên miền, xác minh DNS, cấu hình origin, trạng thái site.  
* FR-C6: Quản lý bảo vệ: custom rule (DSL), rate limit, danh sách IP/Geo/ASN, WAF managed rules, bot, cache, chế độ monitor.  
* FR-C7: Quản lý chứng chỉ TLS (cấp, gia hạn, lưu khóa an toàn, phân phối).  
* FR-C8: Dựng, ký và phân phối snapshot; canary rollout; rollback; kênh khẩn.  
* FR-C9: Quản lý đội edge: đăng ký, định danh mTLS, heartbeat, DNS, cập nhật, gỡ.  
* FR-C10: Nhận log từ edge, lưu ClickHouse, truy vấn cho dashboard, giữ log theo gói, export SIEM (Enterprise).  
* FR-C11: Cảnh báo qua email, Slack (có thể thêm Telegram).  
* FR-C12: API công khai có tài liệu OpenAPI (từ gói Business).  
* FR-C13: Dashboard web: biểu đồ gần thời gian thực (số request, request bị chặn, top IP, top rule).  
* FR-C14: Back-office nội bộ: quản trị tenant, khóa/mở site, cập nhật bộ luật/blocklist, audit.

  ## ***1.3 Yêu cầu phi chức năng (mục tiêu ban đầu, cần đo lại)***

| Hạng mục | Mục tiêu đề xuất |
| ----- | ----- |
| Độ trễ API CRUD | p95 dưới 300 ms |
| Thời gian từ lúc lưu rule đến khi mọi edge áp dụng | dưới 30 giây (mục tiêu) |
| Biểu đồ dashboard 24 giờ | tải dưới 2 giây |
| Khả dụng của control plane | 99,9% (mục tiêu); mất control plane thì edge vẫn chạy |
| Sao lưu | RPO khoảng 5 phút (khôi phục theo thời điểm), RTO khoảng 1 giờ |
| Cô lập dữ liệu | không có truy vấn nào chạy mà thiếu tenant\_id |
| Tiếp nhận log | vài nghìn sự kiện/giây trên cấu hình nhỏ |

  ## ***1.4 Nguyên tắc thiết kế***

1. **Không nằm trên đường request**: edge không gọi control plane khi xử lý traffic.  
2. **Mọi thay đổi cấu hình là một sự kiện** và dẫn tới snapshot mới có version.  
3. **Kiểm tra hợp lệ sớm bằng chính mã của edge**: dùng chung thư viện biên dịch DSL và schema snapshot để không lệch.  
4. **Cô lập tenant** ở mọi lớp (API, truy vấn, row-level security, log).  
5. **Idempotent**: webhook thanh toán, lệnh phát snapshot, job nền đều chạy lại được an toàn.  
6. **Có audit**: mọi thao tác thay đổi đều ghi ai, khi nào, đổi gì.  
7. **Bí mật không đi ra ngoài**: khóa lưu trong KMS/Secrets Manager, không ghi vào log.  
8. **Modular monolith trước, tách service sau** khi có số liệu cho thấy cần.

   ## ***1.5 Ngoài phạm vi***

Xử lý lưu lượng (thuộc data plane); hệ thống ticket hỗ trợ khách hàng (dùng dịch vụ bên thứ ba); tự viết cổng thanh toán (dùng Stripe/PayOS/VNPay).

# **2\. Kiến trúc tổng thể**

## ***2.1 Sơ đồ thành phần***

```
Trình duyệt ─► [Dashboard Next.js] ─► [API (BFF + REST /v1)]
                                          │
        ┌─────────────────────────────────┴──────────────────────────────┐
        │ Modular monolith: auth · tenant · site · rules · billing ·      │
        │ certs · snapshot · edge-fleet · analytics-api · notify · admin  │
        └───────┬──────────────┬───────────────┬───────────────┬─────────┘
            Postgres         Redis       Object storage        NATS
         (nguồn sự thật)  (cache/session) (snapshot, export) (sự kiện, kênh khẩn)

[Workers/Scheduler] ── gia hạn cert, cập nhật blocklist/GeoIP, usage, retention, hóa đơn
[Ingest service]  ◄── log batch từ edge ──► ClickHouse ──► analytics-api ──► Dashboard
Edge nodes ◄── snapshot (long-poll/NATS), override khẩn ──  ──► heartbeat, log, trạng thái
```

## ***2.2 Ranh giới module và thời điểm tách service***

| Module | Trách nhiệm | Dữ liệu sở hữu | Khi nào tách riêng |
| ----- | ----- | ----- | ----- |
| auth | tài khoản, phiên, 2FA | users, sessions | khi dùng Keycloak hoặc cần SSO |
| tenant | tổ chức, thành viên, RBAC, API key | organizations, memberships, api\_keys | ít khi cần |
| billing | gói, đăng ký, thanh toán, hóa đơn | plans, subscriptions, invoices | khi tải webhook lớn |
| site | website, tên miền, origin | sites, domains, origins | ít khi cần |
| rules | rule, rate limit, access list, WAF, bot | các bảng cấu hình bảo vệ | ít khi cần |
| snapshot | dựng, ký, phân phối cấu hình | config\_snapshots | khi số edge và site lớn |
| certs | ACME, lưu và phân phối chứng chỉ | certificates | khi cần cô lập khóa |
| edge-fleet | đăng ký, định danh, DNS, rollout | edges | cùng với snapshot |
| analytics | ingest và truy vấn log | ClickHouse | **sớm nhất** (tải khác hẳn) |
| notify | cảnh báo, email, Slack | alert\_rules, channels | khi tải gửi lớn |

Quy tắc để dễ tách sau này: module chỉ gọi nhau qua interface Go (không truy vấn thẳng bảng của module khác), trao đổi bất đồng bộ bằng sự kiện trên NATS.

## ***2.3 Hợp đồng giữa Control Plane và Data Plane***

| Giao diện | Hướng | Giao thức | Nội dung |
| ----- | ----- | ----- | ----- |
| Đăng ký edge | edge → CP | HTTPS \+ token một lần | nhận định danh mTLS, cấu hình khởi động |
| Snapshot | CP → edge | long-poll GET /v1/snapshot (ETag) \+ thông báo NATS | cấu hình đã ký (Ed25519), có version |
| Kênh khẩn | CP → edge | NATS | ban IP, purge cache, bật/tắt Under Attack |
| Chứng chỉ và bí mật | CP → edge | mTLS | chứng chỉ TLS, khóa HMAC, thông tin origin |
| Log | edge → CP | NATS hoặc HTTPS (nén, gom lô) | sự kiện bảo mật, thống kê theo phút |
| Heartbeat | edge → CP | HTTPS/NATS | version snapshot, tải, lỗi, tuổi snapshot |
| Dữ liệu tham chiếu | CP → edge | qua snapshot hoặc tải riêng có chữ ký | blocklist, GeoIP/ASN, bộ luật WAF |

Schema snapshot và định dạng sự kiện log **dùng chung một module mã nguồn** (waf-core) giữa hai bên để tránh lệch.

# **2.4 Hai luồng điển hình**

**Thêm website mới**

1. Khách nhập tên miền và origin trong dashboard.  
2. API kiểm tra gói còn quota, kiểm tra origin (chống SSRF, xem 5.5).  
3. Hệ thống sinh mã xác minh; khách thêm bản ghi TXT/CNAME.  
4. Job nền kiểm tra DNS; thành công thì site chuyển pending → active.  
5. Module certs cấp chứng chỉ; module snapshot dựng snapshot mới.  
6. Edge nhận snapshot và bắt đầu bảo vệ; dashboard hiển thị CNAME cần trỏ.

**Sửa một rule**

1. Khách lưu rule (có thể ở chế độ chỉ ghi log).  
2. API biên dịch thử bằng waf-core; lỗi thì trả về dòng/cột.  
3. Ghi DB \+ rule\_history \+ audit trong một transaction; phát sự kiện config.changed.  
4. Snapshot builder gom sự kiện (debounce vài giây), dựng snapshot, ký, lưu object storage.  
5. Phát thông báo tới edge; edge xác minh chữ ký, biên dịch, hoán đổi.  
6. Dashboard hiển thị trạng thái áp dụng (số edge đã nhận version mới).

# **3\. Công nghệ và cấu trúc mã nguồn**

## ***3.1 Công nghệ đề xuất***

| Thành phần | Lựa chọn | Ghi chú |
| ----- | ----- | ----- |
| Backend | Go (router chi hoặc Gin) | dùng chung waf-core với edge; bản idea cũng cho phép FastAPI |
| Truy cập DB | pgx \+ sqlc, migration bằng goose hoặc golang-migrate | truy vấn kiểu an toàn |
| CSDL chính | PostgreSQL | người dùng, tenant, domain, rule, gói, hóa đơn |
| Cache/session | Redis | cache cấu hình, bộ đếm, rate limit API |
| Hàng đợi/sự kiện | NATS (hoặc Redis Streams) | nhẹ hơn Kafka |
| Log/analytics | ClickHouse (phương án nhẹ: TimescaleDB hoặc OpenSearch) | cột nén, truy vấn nhanh |
| Lưu snapshot/export | object storage tương thích S3 (S3, Cloudflare R2, MinIO) |  |
| Job nền | River (trên Postgres) hoặc Asynq (trên Redis) | cert, usage, hóa đơn, cập nhật dữ liệu |
| Dashboard | Next.js \+ TypeScript \+ Tailwind \+ TanStack Query \+ ECharts/Recharts |  |
| Xác thực | tự làm (JWT \+ refresh) hoặc Keycloak | Keycloak giúp tiết kiệm thời gian |
| Thanh toán | Stripe; PayOS/VNPay/MoMo cho Việt Nam | dùng bên thứ ba |
| Email | AWS SES hoặc Resend |  |
| Tài liệu API | OpenAPI \+ oapi-codegen | sinh SDK và tài liệu |
| Quan sát | OpenTelemetry, Prometheus, Grafana, Loki |  |
| Kiểm thử | testcontainers, Playwright |  |

**Vì sao nên chọn Go**: dùng chung thư viện DSL, schema snapshot và định dạng log với edge nên validate ở control plane cho đúng như edge sẽ chạy. Nếu chọn FastAPI/Python thì phải gọi một binary hoặc dịch vụ gRPC viết bằng Go để validate DSL, nếu không hai bên sẽ lệch cú pháp.

## ***3.2 Cấu trúc repo gợi ý***

```
controlplane/
  cmd/api/            # HTTP API + BFF
  cmd/worker/         # job nền + scheduler
  cmd/ingest/         # nhận log từ edge
  internal/
    auth/ tenant/ billing/ site/ rules/ certs/
    snapshot/ fleet/ analytics/ notify/ admin/
    platform/         # config, db, redis, nats, kms, logger, otel
  pkg/waf-core/       # DSL compiler, schema snapshot, schema log (dùng chung với edge)
  migrations/         # SQL migration
  openapi/            # spec /v1
  web/                # Dashboard Next.js
  deploy/             # Dockerfile, Terraform, docker-compose
  test/               # integration, contract test với edge, e2e
```

# **4\. Mô hình dữ liệu (PostgreSQL)**

## ***4.1 Nguyên tắc***

* Khóa chính UUID (v7 để có thứ tự thời gian); mọi bảng của tenant có cột tenant\_id.  
* Mọi bảng có created\_at, updated\_at; xóa mềm cho thực thể quan trọng (site, rule).  
* Cấu hình linh hoạt lưu JSONB kèm schema\_version.  
* Tiền lưu bằng số nguyên đơn vị nhỏ nhất kèm mã tiền tệ (tránh số thực).  
* **Row-level security** bật cho mọi bảng của tenant (xem 4.3).

  ## ***4.2 Các bảng chính***

| Bảng | Cột chính | Ghi chú |
| ----- | ----- | ----- |
| users | id, email (duy nhất), password\_hash, email\_verified\_at, totp\_secret\_enc, status | băm mật khẩu bằng argon2id; TOTP mã hóa |
| organizations | id, name, owner\_user\_id, plan\_id, status | cá nhân cũng là một tổ chức một người |
| memberships | tenant\_id, user\_id, role | role: owner, admin, viewer |
| invitations | tenant\_id, email, role, token\_hash, expires\_at | lưu băm của token |
| refresh\_tokens | id, user\_id, family\_id, token\_hash, ua, ip, expires\_at, revoked\_at | xoay vòng, phát hiện dùng lại |
| api\_keys | id, tenant\_id, name, key\_hash, scopes, last\_used\_at, expires\_at | chỉ hiển thị khóa một lần |
| plans | id, code, price\_minor, currency, interval, entitlements (jsonb), version | Free, Pro, Business, Enterprise |
| subscriptions | id, tenant\_id, plan\_id, status, provider, provider\_sub\_id, period\_start, period\_end, cancel\_at |  |
| invoices | id, tenant\_id, amount\_minor, currency, status, provider\_ref, issued\_at |  |
| webhook\_events | provider, event\_id (duy nhất), payload, processed\_at | chống xử lý trùng |
| sites | id, tenant\_id, name, status, fail\_mode | status: pending, active, suspended |
| domains | id, site\_id, tenant\_id, hostname (duy nhất), verification\_token, verified\_at |  |
| origins | id, site\_id, url, weight, host\_header, tls\_mode, health |  |
| waf\_settings | site\_id, mode, sensitivity, body\_limit\_kb, ruleset\_version, exclusions (jsonb) |  |
| rules | id, site\_id, priority, expression, action, action\_params, mode, enabled, expires\_at, version | mode: log hoặc enforce |
| rate\_limit\_policies | id, site\_id, match\_expr, key, limit, window\_s, action, ban\_s |  |
| access\_lists | id, site\_id, type, value, action, note | type: ip, cidr, country, asn |
| bot\_settings / cache\_settings | site\_id, các tham số |  |
| certificates | id, domain\_id, status, not\_after, secret\_ref, issuer | khóa riêng nằm trong KMS/Secrets Manager |
| edges | id, region, provider, status, snapshot\_version, last\_heartbeat\_at, cert\_serial |  |
| config\_snapshots | id, scope, version, checksum, signature, object\_key, rollout\_state, created\_at | scope: global, vùng, site |
| rule\_history | entity, entity\_id, version, diff, actor, at | phục vụ rollback |
| alert\_rules, notification\_channels, alerts | điều kiện, kênh, trạng thái |  |
| audit\_logs | id, tenant\_id, actor\_type, actor\_id, action, entity, entity\_id, ip, ua, diff, at | chỉ thêm, không sửa |
| usage\_counters | tenant\_id, period, requests, bytes\_out, rules\_count | phục vụ quota và hóa đơn |

  ## ***4.3 Cô lập tenant bằng row-level security***

```sql
ALTER TABLE sites ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sites
  USING (tenant_id = current_setting('app.tenant_id')::uuid);
```

Mỗi request, API mở transaction và chạy SET LOCAL app.tenant\_id \= ... trước mọi truy vấn. Tài khoản DB dùng cho API **không** có quyền bỏ qua RLS; chỉ role riêng của back-office và job nền mới được phép, và các truy cập đó đều ghi audit.

# **5\. Chi tiết từng module**

## ***5.1 Auth và Identity***

**Mục đích**: tạo tài khoản, xác thực an toàn, cấp phiên làm việc.

**Đăng ký**

1. Nhập email và mật khẩu (tối thiểu 10 ký tự, có thể đối chiếu danh sách mật khẩu bị lộ bằng dịch vụ kiểu k-anonymity).  
2. Tạo trong **một transaction**: user, tổ chức cá nhân, membership vai trò owner, subscription gói Free.  
3. Gửi email xác minh: token ngẫu nhiên 32 byte, **lưu băm**, hạn 24 giờ. Chưa xác minh email thì chưa thêm được website.

**Đăng nhập**

* Băm mật khẩu bằng **argon2id**; giới hạn tốc độ theo IP và theo tài khoản (Redis); khóa tạm sau nhiều lần sai.  
* Nếu bật 2FA: yêu cầu mã TOTP (chuẩn RFC 6238, bước 30 giây, cho lệch 1 bước) hoặc một trong 10 mã dự phòng dùng một lần (lưu băm).  
* Phản hồi lỗi **không lộ** email có tồn tại hay không.

**Token và phiên**

* Access token là JWT ngắn hạn (khoảng 15 phút), ký bằng khóa bất đối xứng (EdDSA/ES256) giữ trong KMS; chứa user\_id, tenant\_id đang chọn, vai trò.  
* Refresh token là chuỗi ngẫu nhiên, lưu băm, hạn khoảng 30 ngày, **xoay vòng mỗi lần dùng**; nếu một token cũ bị dùng lại thì thu hồi cả chuỗi (family\_id).  
* Refresh token nằm trong cookie HttpOnly; Secure; SameSite=Lax; access token giữ trong bộ nhớ trình duyệt.  
* Đặt lại mật khẩu: token một lần, hạn 1 giờ, xong thì thu hồi mọi phiên. Trang phiên cho phép xem thiết bị và đăng xuất từng phiên.

**Tùy chọn**: dùng Keycloak để có sẵn đăng ký, 2FA, đăng nhập Google/GitHub; khi đó module auth chỉ còn kiểm tra token và ánh xạ user sang tenant.

**Kiểm thử**: luồng đăng ký/đăng nhập/2FA, tái sử dụng refresh token, brute force, hết hạn token, tìm lỗ hổng bằng OWASP ZAP trên môi trường của nhóm.

## ***5.2 Tenant và phân quyền (RBAC)***

Một user có thể thuộc nhiều tổ chức; mỗi request mang tenant\_id và middleware kiểm tra membership trước khi vào handler.

| Hành động | owner | admin | viewer |
| ----- | ----- | ----- | ----- |
| Xem website, báo cáo | ✓ | ✓ | ✓ |
| Sửa rule và cấu hình bảo vệ | ✓ | ✓ | – |
| Thêm/xóa website | ✓ | ✓ | – |
| Mời/xóa thành viên | ✓ | ✓ (không đổi owner) | – |
| Quản lý API key | ✓ | ✓ | – |
| Thanh toán, đổi gói | ✓ | – | – |
| Xóa tổ chức, chuyển quyền owner | ✓ | – | – |

* Mọi quyết định đi qua một hàm duy nhất can(user, action, resource); có test bao phủ toàn bộ ma trận.  
* **API key** gắn với tenant và có **scope** (ví dụ sites:read, rules:write, analytics:read); quyền không vượt quá vai trò của người tạo. Chỉ hiển thị khóa một lần, lưu băm, có hạn dùng và ghi last\_used\_at.  
* Lời mời thành viên dùng token một lần, hạn 7 ngày.

  ## ***5.3 Gói dịch vụ và entitlement***

Mỗi gói là một bản ghi plans với trường entitlements (JSONB, có version). Ví dụ gói Pro:

```
plan: pro
version: 7
limits:
  sites: 5
  custom_rules: 20
  rate_limit_policies: 5
  waf_body_kb: 64
  log_retention_days: 7
features:
  waf_managed: full
  bot: js_challenge
  geo_block: true
  asn_block: false
  cache: true
  api_access: false
  siem_export: false
```

**Nguồn giá trị quota**: bảng quota ở mục 5.15 của tài liệu Data Plane là nguồn gốc; control plane nạp các giá trị đó vào bảng plans.

**Kiểm tra ở ba chỗ**

1. **API**: từ chối khi tạo/sửa vượt quota (trả mã lỗi rõ và gợi ý nâng gói).  
2. **Snapshot builder**: cắt cấu hình vượt gói trước khi phát.  
3. **Edge**: bỏ qua tính năng không thuộc gói (phòng khi hạ gói mà snapshot chưa kịp cập nhật).

**Đo mức dùng**: job mỗi giờ tổng hợp số request và băng thông từ ClickHouse vào usage\_counters. Cảnh báo khi đạt 80% và 100% hạn mức; khi vượt thì **hạ tính năng và báo khách, không chặn lưu lượng hợp lệ**.

**Nâng/hạ gói**: nâng có hiệu lực ngay; hạ có hiệu lực cuối kỳ. Nếu cấu hình hiện tại vượt gói thấp hơn, yêu cầu khách giảm trước hoặc tự vô hiệu hóa phần vượt theo thứ tự ưu tiên đã báo trước (rule tạo gần nhất bị tắt trước).

## ***5.4 Thanh toán và hóa đơn (dùng bên thứ ba)***

**Stripe (thẻ quốc tế)**

1. Tạo Checkout Session chế độ subscription, chuyển khách sang trang thanh toán.  
2. Nhận webhook (checkout.session.completed, invoice.paid, invoice.payment\_failed, customer.subscription.updated/deleted) rồi cập nhật subscriptions.  
3. Đổi thẻ, hủy gói: dùng customer portal của Stripe để giảm khối lượng phải tự làm.

**PayOS/VNPay/MoMo (Việt Nam)**: nhiều cổng chỉ hỗ trợ thanh toán một lần, nên dùng mô hình **gói trả trước theo kỳ**: tạo hóa đơn → link thanh toán → nhận IPN/webhook xác nhận → job nhắc gia hạn trước 7, 3, 1 ngày → quá hạn có **thời gian ân hạn** (ví dụ 7 ngày) rồi hạ về Free.

**Xử lý webhook an toàn**

* Xác minh chữ ký; ghi webhook\_events (khóa duy nhất event\_id) **trước** khi xử lý để chống xử lý trùng; trả 2xx nhanh, xử lý trong job nền.  
* Sự kiện đến muộn hoặc sai thứ tự: khi mâu thuẫn, lấy trạng thái từ API nhà cung cấp; job đối soát chạy hằng ngày.

**Máy trạng thái subscription**: active → past\_due → (ân hạn) → canceled/downgraded; Free luôn active.

**Lưu ý**: không lưu dữ liệu thẻ (chỉ lưu mã tham chiếu của nhà cung cấp); hóa đơn có số tuần tự và bản PDF; yêu cầu hóa đơn điện tử/thuế tại Việt Nam cần hỏi ý kiến kế toán hoặc chuyên gia, tài liệu này không đưa kết luận pháp lý. Môi trường phát triển dùng chế độ sandbox/test của nhà cung cấp.

## ***5.5 Quản lý website và tên miền***

**Trạng thái site**: pending\_dns → active → suspended (hết hạn gói, vi phạm điều khoản hoặc admin khóa) → deleted.

**Xác minh tên miền**

1. Sinh mã xác minh; khách thêm bản ghi TXT \_waf-verify.\<tên miền\> hoặc CNAME về tên miền của hệ thống.  
2. Job kiểm tra DNS mỗi phút trong 24 giờ đầu, sau đó thưa dần; thành công thì chuyển active.  
3. hostname là duy nhất toàn hệ thống: tên miền đã được tenant khác xác minh thì bị từ chối; có quy trình tranh chấp do admin xử lý.  
4. Wildcard cần xác minh bằng DNS-01 (xem 5.7).

**Kiểm tra origin (khớp Data Plane 5.11)**

* Chỉ http/https; cổng thuộc danh sách cho phép (80, 443, 8080, 8443 và tùy chọn khác).  
* Phân giải DNS rồi **từ chối** IP loopback, dải riêng, link-local và địa chỉ metadata cloud.  
* Thử kết nối bằng **worker cô lập mạng** (không truy cập được hạ tầng nội bộ của control plane) để tránh SSRF nhằm vào chính hệ thống.

**Hướng dẫn cho khách**: dashboard hiển thị CNAME cần trỏ; khuyến nghị khóa origin chỉ nhận IP của edge (danh sách IP công khai qua API /v1/edge-ips) hoặc kiểm tra header bí mật X-Origin-Auth. Tên miền gốc (apex) không đặt được CNAME ở nhiều nhà cung cấp DNS, cần hướng dẫn dùng ALIAS/ANAME hoặc bản ghi A (nhóm cần chốt, xem mục 15).

## ***5.6 Quản lý rule và cấu hình bảo vệ***

**Đối tượng**: custom rule, chính sách rate limit, danh sách IP/Geo/ASN, WAF managed (mức nhạy, paranoia, exclusions), bot, cache.

**Pipeline kiểm tra trước khi lưu**

1. Kiểm tra schema và quyền.  
2. Kiểm tra quota theo gói.  
3. **Biên dịch DSL bằng waf-core**: cú pháp, kiểu dữ liệu, độ dài biểu thức, regex RE2 hợp lệ và trong giới hạn kích thước; lỗi trả về dòng/cột.  
4. Phát hiện xung đột (ví dụ một rule allow che hết các rule phía sau) và đưa ra **cảnh báo**.  
5. **Chạy thử trên log gần nhất** của site (nếu có): ước tính rule sẽ khớp bao nhiêu phần trăm lưu lượng 24 giờ, hiển thị trước khi bật chế độ chặn.

**Vòng đời rule**: tạo ở chế độ log (chỉ ghi) → xem số khớp trên dashboard → chuyển sang enforce. Rule có thể đặt expires\_at.

**Phiên bản và hoàn tác**: mọi thay đổi ghi vào rule\_history; hoàn tác là tạo thay đổi mới trỏ về bản cũ (không xóa lịch sử).

**Chống ghi đè**: khóa lạc quan bằng cột version/ETag (If-Match); hai người sửa cùng lúc thì người sau nhận lỗi xung đột kèm bản mới nhất.

**Giao diện**: trình dựng rule (chọn trường, toán tử, giá trị rồi sinh DSL) và chế độ nâng cao gõ DSL trực tiếp, có gợi ý và đánh dấu lỗi. Hỗ trợ nhập/xuất YAML-JSON và sắp xếp lại thứ tự ưu tiên hàng loạt.

**Managed ruleset**: chọn phiên bản và độ nhạy; exclusions chỉ chấp nhận rule\_id có trong bộ luật đang chọn.

**Danh sách truy cập**: nhập CSV, kiểm tra CIDR hợp lệ, giới hạn số dòng theo gói.

Sau khi ghi thành công, phát sự kiện config.changed kèm tenant\_id, site\_id, phạm vi.

## ***5.7 Quản lý chứng chỉ TLS***

1. Khi domain được xác minh, job tạo đơn ACME (certmagic hoặc lego chạy ở control plane).  
2. **Cách xác thực**: HTTP-01 (control plane gửi token cho edge qua kênh khẩn để edge trả lời tại /.well-known/acme-challenge/); wildcard cần DNS-01, khách tạo CNAME \_acme-challenge về vùng DNS do hệ thống quản lý.  
3. **Khóa riêng** được sinh và lưu trong KMS/Secrets Manager (mã hóa phong bì); certificates.secret\_ref chỉ trỏ tới nơi lưu. Edge nhận qua mTLS.  
4. **Gia hạn**: job quét chứng chỉ còn dưới 30 ngày; chứng chỉ Let’s Encrypt có thời hạn ngắn (hiện khoảng 90 ngày, có thể thay đổi) nên gia hạn phải hoàn toàn tự động; lỗi thì thử lại có lùi dần, cảnh báo khi còn dưới 14 ngày.  
5. **Giới hạn của nhà cấp**: xếp hàng cấp chứng chỉ, ưu tiên domain mới, tránh cấp trùng, dùng môi trường staging khi phát triển.  
6. **Khi cấp thất bại**: edge dùng chứng chỉ mặc định; dashboard hiển thị trạng thái và hướng dẫn khắc phục.  
7. **Chứng chỉ do khách cung cấp** (Enterprise): tải PEM lên, kiểm tra chuỗi, khớp khóa và hạn dùng.  
8. Thu hồi/xóa chứng chỉ khi xóa site.

   ## ***5.8 Dựng và phân phối snapshot***

**Mục đích**: biến cấu hình trong DB thành snapshot đã kiểm tra, đã ký, và đưa tới mọi edge một cách an toàn.

**Các bước**

1. Nhận config.changed, gộp theo tenant/site và **debounce** vài giây để nhiều thay đổi liên tiếp chỉ tạo một snapshot.  
2. Đọc cấu hình đã commit trong một transaction nhất quán, **áp entitlement** (cắt phần vượt gói), biên dịch thử mọi rule bằng waf-core.  
3. **Cô lập lỗi theo site**: nếu cấu hình của một site không hợp lệ, loại site đó khỏi bản mới và giữ bản cũ của site đó, đồng thời tạo cảnh báo nội bộ; không để một site hỏng làm hỏng snapshot của cả vùng.  
4. Tăng version toàn cục (số nguyên đơn điệu), tính checksum SHA-256, **ký Ed25519** (khóa ký quản lý trong KMS/Secrets Manager), nén gzip, lưu object storage (snapshots/\<vùng\>/\<version\>.json.gz) và metadata vào config\_snapshots.  
5. **Phát hành**: cập nhật con trỏ latest của vùng, phát thông báo NATS config.updated; endpoint GET /v1/snapshot?since=\<version\> trả 200 kèm nội dung hoặc 304\.  
6. **Canary**: chỉ nhóm edge canary nhận con trỏ mới trước; sau vài phút nếu tỷ lệ lỗi/chặn không vượt ngưỡng (đọc từ heartbeat và log) thì mở cho các edge còn lại; vượt ngưỡng thì dừng và tự hoàn tác.  
7. **Theo dõi**: cột edges.snapshot\_version cho dashboard hiển thị đã áp dụng trên N/M edge.  
8. **Rollback**: đặt con trỏ về version trước; giữ lại tối thiểu 50 bản hoặc 30 ngày.  
9. **Kênh khẩn**: API nội bộ phát lệnh override (ban IP, purge cache, Under Attack) qua NATS có chữ ký; edge áp dụng trong vài giây; lệnh cũng được ghi vào DB để lần snapshot sau gộp lại.

**Bí mật** (khóa HMAC challenge, thông tin origin) không để dạng rõ trong snapshot: mã hóa phong bì riêng cho từng edge.

**Chế độ lỗi**: object storage lỗi → edge giữ bản đang chạy; NATS lỗi → edge vẫn long-poll; ký lỗi → không phát hành; snapshot quá lớn → chuyển sang snapshot theo site hoặc delta.

**Kiểm thử**: contract test với edge thật dùng chung schema, snapshot hỏng, rollback, canary dừng giữa chừng, mất kết nối giữa chừng.

## ***5.9 Quản lý đội edge (Edge Fleet)***

**Mục đích**: biết có những edge nào, khỏe hay không, và thêm/gỡ/cập nhật chúng một cách tự động (khớp mục 8.1 của tài liệu Data Plane).

**Đăng ký và định danh**

1. Terraform/admin tạo **token bootstrap dùng một lần** (lưu băm, hạn 1 giờ, gắn vùng và nhà cung cấp).  
2. Edge gọi POST /internal/edges/register kèm token và CSR; control plane kiểm tra rồi cấp **chứng chỉ mTLS ngắn hạn** từ CA nội bộ (ví dụ step-ca hoặc Vault PKI), edge tự gia hạn.  
3. Chứng chỉ gắn edge\_id và vùng; control plane chỉ trả bí mật của site cho edge thuộc vùng được phép.

**Heartbeat** (15–30 giây/lần): version snapshot, tuổi snapshot, CPU/RAM, RPS, tỷ lệ lỗi, p99, hạn chứng chỉ, số log bị bỏ. Trạng thái edge: registering → ready → degraded → draining → offline → decommissioned.

**DNS**: khi edge ready đủ N lần heartbeat liên tiếp thì thêm bản ghi (latency/geolocation) qua API của nhà cung cấp DNS; khi offline thì rút. Có chống dao động (cần N lần liên tiếp) và **chốt an toàn**: không bao giờ rút edge cuối cùng của một vùng chỉ vì một lần mất heartbeat, và giới hạn tỷ lệ edge bị rút cùng lúc.

**Cập nhật phần mềm edge**: canary một vùng → lần lượt các vùng; với mỗi edge: lệnh drain qua kênh khẩn → chờ kết nối cũ → CI/Terraform thay ảnh → xác nhận heartbeat có version mới.

**Gỡ edge**: drain → rút DNS → thu hồi chứng chỉ mTLS và token → hủy tài nguyên.

**Khi nghi edge bị xâm nhập**: thu hồi chứng chỉ ngay, xoay khóa HMAC liên quan, phát snapshot mới. Edge không giữ khóa dài hạn trên đĩa nên phạm vi ảnh hưởng nhỏ.

## ***5.10 Pipeline log và analytics***

**Dịch vụ ingest**

1. Nhận lô sự kiện từ edge (NATS logs.\<vùng\> hoặc HTTPS nén), xác thực mTLS.  
2. Kiểm tra schema bằng waf-core; **đối chiếu site\_id với tenant\_id** từ cache Redis (không tin hoàn toàn giá trị edge gửi).  
3. Gắn retention\_days theo gói của tenant.  
4. Ghi ClickHouse theo lô (gom 1 giây hoặc 10.000 dòng; có thể dùng async insert). Lô lỗi vào hàng đợi dead-letter để xử lý lại.

**Schema ClickHouse**

```sql
CREATE TABLE security_events (
  ts DateTime64(3), tenant_id UUID, site_id UUID, edge_id String,
  region LowCardinality(String), client_ip IPv6, country LowCardinality(String),
  asn UInt32, method LowCardinality(String), host String, path String,
  status UInt16, action LowCardinality(String), rule_id String,
  waf_score UInt16, bot_score UInt8, latency_ms UInt32, retention_days UInt16
) ENGINE = MergeTree
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, site_id, ts)
TTL toDateTime(ts) + toIntervalDay(retention_days);

CREATE TABLE site_stats_1m (
  minute DateTime, tenant_id UUID, site_id UUID,
  requests UInt64, blocked UInt64, challenged UInt64, rate_limited UInt64,
  cache_hits UInt64, bytes_out UInt64, status_5xx UInt64
) ENGINE = SummingMergeTree
PARTITION BY toYYYYMM(minute)
ORDER BY (tenant_id, site_id, minute);
```

site\_stats\_1m nhận số liệu **tổng hợp theo phút do edge gửi**, nên biểu đồ vẫn chính xác dù log request bình thường chỉ được lấy mẫu; top IP/top rule truy vấn từ security\_events.

**Giữ dữ liệu**: TTL theo retention\_days. TTL của ClickHouse chạy nền nên dữ liệu quá hạn có thể tồn tại ngắn; API truy vấn vẫn **luôn lọc theo số ngày của gói**.

**API truy vấn** (/v1/sites/{id}/analytics/...): luôn thêm điều kiện tenant\_id lấy từ token và kiểm tra site thuộc tenant qua Postgres; giới hạn khoảng thời gian theo gói, giới hạn số dòng, đặt timeout truy vấn, cache kết quả 10–30 giây trong Redis. Dashboard làm mới mỗi 10 giây (hoặc SSE).

**Export SIEM (Enterprise)**: cấu hình đích (webhook HTTPS có ký HMAC, S3, syslog); job đẩy lô sự kiện dạng JSON (tùy chọn CEF), lưu con trỏ đã gửi, thử lại khi lỗi.

**Quyền riêng tư**: tùy chọn che một phần IP theo tenant; không có body trong log; khi tenant xóa tài khoản, job xóa dữ liệu theo tenant\_id (thao tác xóa trong ClickHouse nặng, nên chạy theo lô ngoài giờ cao điểm).

**Kiểm thử**: tải ingest, lô lỗi/trùng, retention, kiểm tra không truy vấn nào thiếu tenant\_id.

## ***5.11 Cảnh báo và thông báo***

| Loại cảnh báo | Điều kiện | Mức |
| ----- | ----- | ----- |
| Tấn công đang diễn ra | RPS vượt baseline hoặc Under Attack tự bật | cao |
| Origin lỗi | tỷ lệ 5xx/timeout từ origin vượt ngưỡng vài phút | cao |
| Chứng chỉ | còn dưới 14 ngày hoặc cấp thất bại | cao |
| Cấu hình bị từ chối | snapshot loại site vì lỗi | cao |
| Quota | đạt 80% và 100% | trung bình |
| Thanh toán | thanh toán thất bại, gói sắp hết hạn | trung bình |
| Domain chưa xác minh | sau 24 và 72 giờ | thấp |

**Cơ chế**: bộ đánh giá chạy mỗi phút trên số liệu từ ClickHouse, Postgres và heartbeat, tạo bản ghi alerts (open → ack → resolved) rồi gửi qua kênh của tenant (email bằng SES/Resend, Slack incoming webhook, tùy chọn Telegram).

**Chống nhiễu**: loại trùng theo (rule, site) trong một cửa sổ, giới hạn tần suất (ví dụ 1 lần/15 phút), gom nhóm, giờ yên lặng tùy chọn, gửi thông báo “đã khôi phục”.

**Email**: cấu hình SPF/DKIM/DMARC, mẫu hai ngôn ngữ vi/en. **Webhook của khách** phải qua kiểm tra SSRF như 5.5 và được ký HMAC. Theo bảng gói, Free không có cảnh báo tuỳ chỉnh (chỉ thông báo hệ thống như xác minh email, thanh toán).

## ***5.12 API công khai và API key***

**Nguyên tắc**: REST JSON dưới /v1, OpenAPI là nguồn sự thật, dashboard dùng **cùng API** và cùng cơ chế phân quyền.

* Phân trang bằng cursor; lỗi theo định dạng problem+json (RFC 9457\) kèm request\_id.  
* Idempotency-Key cho các POST; ETag/If-Match cho cập nhật.  
* Giới hạn tốc độ theo gói (token bucket trên Redis), trả 429 kèm Retry-After.  
* Phiên bản: /v1 ổn định; thay đổi phá vỡ sang /v2 kèm header báo ngừng hỗ trợ.  
* CORS chỉ cho tên miền dashboard; endpoint dùng cookie phải có CSRF token.  
* Quyền truy cập API bằng key chỉ mở từ gói Business trở lên (theo bảng gói).

| Nhóm | Endpoint tiêu biểu |
| ----- | ----- |
| Auth | POST /v1/auth/register, /login, /refresh, /logout, /2fa/enable |
| Tổ chức | GET/PATCH /v1/org, GET/POST /v1/org/members, /v1/api-keys |
| Website | GET/POST /v1/sites, GET/PATCH/DELETE /v1/sites/{id}, POST /v1/sites/{id}/verify |
| Rule | GET/POST /v1/sites/{id}/rules, POST .../rules/validate, POST .../rules/{rid}/rollback |
| Chính sách | /v1/sites/{id}/rate-limits, /access-lists, /waf, /bot, /cache |
| Chứng chỉ | GET /v1/sites/{id}/certificates |
| Analytics | GET /v1/sites/{id}/analytics/overview, /timeseries, /top |
| Thanh toán | GET /v1/billing/plans, POST /v1/billing/checkout, /portal, GET /v1/billing/invoices |
| Cảnh báo | /v1/alert-rules, /v1/channels, /v1/alerts |
| Công khai | GET /v1/edge-ips |
| Nội bộ (mTLS, không công khai) | POST /internal/edges/register, GET /internal/snapshot, POST /internal/heartbeat, POST /internal/logs |

**Ví dụ tạo rule**

```
POST /v1/sites/{site_id}/rules
Content-Type: application/json
Idempotency-Key: 7c1f0a52-3b9e-4d0b-9a77-1d2e5c8f9a10

{
  "priority": 10,
  "expression": "http.path starts_with '/admin' and ip.geo.country != 'VN'",
  "action": "block",
  "mode": "log"
}

201 Created
{ "id": "r_1", "version": 1, "warnings": [], "applied_edges": "0/3" }
```

## ***5.13 Dashboard (Next.js)***

**Các màn hình**: đăng nhập/đăng ký; **wizard thêm website** (4 bước: nhập tên miền và origin → xác minh DNS → chọn mức bảo vệ mặc định → kiểm tra kết nối); tổng quan (số request, chặn, challenge, top quốc gia/IP/rule theo 24 giờ, 7 ngày, 30 ngày tùy gói); trang chi tiết site (sự kiện bảo mật, WAF, rule, rate limit, danh sách truy cập, bot, cache, TLS, origin, cài đặt); thanh toán và hóa đơn; thành viên và API key; cảnh báo và kênh thông báo; audit log.

**Quyết định giao diện**

* Hiển thị trạng thái “đang áp dụng cấu hình trên n/m edge” sau mỗi thay đổi.  
* Chế độ monitor nổi bật, kèm nút “chuyển sang chặn” sau khi xem số khớp.  
* Bật/tắt Under Attack có bước xác nhận.  
* Hiển thị request\_id và lý do chặn để tra cứu từ trang chặn.  
* Hai ngôn ngữ vi/en, hỗ trợ truy cập (accessibility), giao diện co giãn trên điện thoại.

**Bảo mật giao diện (quan trọng)**: đường dẫn, User-Agent, tham số trong log **do kẻ tấn công kiểm soát**, nên phải escape mọi dữ liệu hiển thị để tránh XSS vào chính dashboard. Dùng CSP chặt, không script nội tuyến; access token chỉ giữ trong bộ nhớ, refresh token trong cookie HttpOnly.

**Kiểm thử**: Playwright cho các luồng chính (đăng ký, thêm site, sửa rule, nâng gói, xem analytics), kèm kiểm thử XSS với payload trong log mẫu.

## ***5.14 Back-office nội bộ***

* Tìm kiếm tenant/user/site; xem trạng thái, sức khỏe edge; khóa/mở site hoặc tenant; cấp hoặc gia hạn gói thủ công.  
* Quản lý managed ruleset (đăng bản mới, đặt bản mặc định, rollout), danh sách blocklist toàn cục, bảng plans, feature flag.  
* **Impersonation** (xem với tư cách khách để hỗ trợ): chỉ đọc, bắt buộc nhập lý do, có thời hạn ngắn, ghi audit.  
* Đăng nhập admin bắt buộc 2FA, chỉ truy cập từ mạng nội bộ/VPN; vai trò riêng (support, ops, superadmin); mọi hành động ghi audit không sửa được.

  ## ***5.15 Job nền và scheduler***

| Job | Tần suất | Việc làm |
| :---- | :---- | :---- |
| verify\_domains | mỗi phút | kiểm tra DNS cho site pending\_dns |
| issue/renew\_certificates | liên tục \+ hằng ngày | cấp và gia hạn chứng chỉ |
| build\_snapshot | theo sự kiện | xem 5.8 |
| evaluate\_alerts | mỗi phút | đánh giá cảnh báo |
| edge\_health\_sweeper | 30 giây | cập nhật trạng thái edge, rút DNS khi cần |
| aggregate\_usage | hằng giờ | cập nhật usage\_counters |
| export\_siem | mỗi phút | đẩy log cho tenant Enterprise |
| send\_renewal\_reminders | hằng ngày | nhắc gia hạn trước 7, 3, 1 ngày |
| billing\_reconcile | hằng ngày | đối soát với nhà cung cấp thanh toán |
| update\_blocklists / update\_geoip | 6–24 giờ / định kỳ | xem 5.16 |
| publish\_managed\_rules | khi có bản mới | xem 5.16 |
| retention\_cleanup | hằng ngày | dọn dữ liệu Postgres theo chính sách |
| backup\_verify | hằng tuần | thử khôi phục bản sao lưu |

**Cơ chế**: River hoặc Asynq; scheduler chạy một nơi nhờ advisory lock/leader election; mỗi job có khóa idempotent, retry lùi dần, timeout, dead-letter và metric riêng.

## ***5.16 Dữ liệu tham chiếu và bộ luật managed***

Control plane cung cấp cho edge: blocklist (Spamhaus DROP, FireHOL), GeoIP/ASN, managed ruleset.

**Pipeline dữ liệu tham chiếu**: tải theo lịch → kiểm tra định dạng và kích thước → **chặn bản bất thường** (bản mới nhỏ đi hoặc thay đổi lớn bất thường thì giữ bản cũ và cảnh báo) → chuẩn hóa → ghi version → đưa vào snapshot (blocklists\_version).

**Giấy phép**: kiểm tra điều khoản từng nguồn (GeoLite2 cần tài khoản và có điều kiện sử dụng; các blocklist có điều khoản riêng); không phân phối lại dữ liệu mà điều khoản cấm.

**Phát hành managed ruleset**: thay đổi luật qua pull request → CI chạy bộ mẫu tấn công và bộ mẫu sạch (TPR/FPR không được xấu đi) → phát hành beta ở chế độ monitor cho tenant nội bộ → rollout tăng dần → có thể rollback; mỗi bản có changelog. Có đường phát hành khẩn cho virtual patching khi xuất hiện lỗ hổng mới.

# **6\. Bảo mật control plane**

Control plane giữ khóa, cấu hình và dữ liệu của mọi khách, nên là mục tiêu giá trị cao hơn từng edge.

## ***6.1 Mối đe dọa chính và biện pháp***

| Mối đe dọa | Biện pháp |
| ----- | ----- |
| Truy cập chéo tenant (IDOR) | tenant\_id lấy từ token, row-level security, UUID, test tự động đổi ID giữa hai tenant |
| Chiếm tài khoản | argon2id, 2FA, giới hạn tốc độ, xoay refresh token, báo đăng nhập từ thiết bị lạ |
| XSS/CSRF vào dashboard | CSP chặt, escape dữ liệu log, SameSite, CSRF token |
| SSRF qua origin, webhook của khách | kiểm tra dải IP, worker cô lập mạng, danh sách cổng cho phép, kiểm tra lại lúc kết nối |
| Webhook thanh toán giả | xác minh chữ ký, idempotency, đối soát hằng ngày |
| Lộ khóa ký snapshot hoặc khóa TLS | lưu trong KMS, quyền tối thiểu, ký ngay trong KMS nếu được, xoay khóa, audit mọi truy cập |
| Snapshot độc hại đến edge | chữ ký Ed25519, mTLS, kiểm tra ở edge, canary |
| Edge giả mạo | token một lần, chứng chỉ mTLS ngắn hạn, CA nội bộ, thu hồi nhanh |
| Lạm dụng cấp chứng chỉ hoặc làm proxy mở | chỉ phục vụ tên miền đã xác minh, quota, giới hạn tốc độ |
| Lộ dữ liệu log | mã hóa, luôn lọc theo tenant, redact, retention theo gói |
| Nhân sự nội bộ lạm quyền | RBAC riêng, 2FA, VPN, audit không sửa được, impersonation hạn chế |
| Tấn công DoS vào API/dashboard | giới hạn tốc độ, cache, đặt chính dashboard sau sản phẩm WAF (có đường vào dự phòng để không phụ thuộc vòng tròn) |
| Chuỗi cung ứng | govulncheck, Dependabot/npm audit, ghim phiên bản, quét ảnh container, SBOM |

## ***6.2 Quản lý khóa và bí mật (đề xuất, nhóm chốt)***

| Loại | Nơi lưu | Xoay khóa |
| ----- | ----- | ----- |
| Khóa ký JWT | KMS | khoảng 90 ngày, hỗ trợ nhiều kid cùng lúc |
| Khóa ký snapshot (Ed25519) | KMS/Secrets Manager | khoảng 180 ngày hoặc ngay khi nghi lộ; edge giữ nhiều khóa công khai |
| Khóa riêng TLS của khách | KMS/Secrets Manager (mã hóa phong bì) | theo chu kỳ gia hạn chứng chỉ |
| Khóa HMAC challenge theo site | Secrets Manager | khoảng 30 ngày, giữ bản cũ đến hết hạn cookie |
| Khóa API của Stripe, SES, DNS | Secrets Manager | khi nhân sự thay đổi hoặc nghi lộ |
| Mật khẩu DB | Secrets Manager, ưu tiên thông tin xác thực ngắn hạn | định kỳ |

## ***6.3 Mã hóa và dữ liệu***

* TLS cho mọi kết nối; mã hóa đĩa của DB và object storage; sao lưu được mã hóa.  
* Mã hóa cột nhạy cảm (totp\_secret\_enc, bí mật origin) bằng mã hóa phong bì.  
* Không ghi bí mật hoặc dữ liệu cá nhân thừa vào log hệ thống; thu thập dữ liệu cá nhân ở mức tối thiểu.

  ## ***6.4 Quyền riêng tư và tuân thủ***

* Cần chính sách quyền riêng tư, điều khoản sử dụng và thỏa thuận xử lý dữ liệu. Log chứa IP là dữ liệu cá nhân ở nhiều khu vực.  
* Hỗ trợ xuất và xóa dữ liệu theo yêu cầu; thời hạn giữ log theo gói.  
* Tại Việt Nam cần tham khảo quy định về bảo vệ dữ liệu cá nhân (Nghị định 13/2023/NĐ-CP) và lưu ý dữ liệu đi qua nhiều quốc gia khi edge đặt ở nhiều vùng. Tài liệu này **không** đưa kết luận pháp lý; nhóm nên hỏi chuyên gia trước khi nhận khách thật.  
* Điều khoản cấm dùng dịch vụ cho nội dung bất hợp pháp và có quy trình xử lý báo cáo lạm dụng.

  ## ***6.5 Audit log***

Ghi: đăng nhập, đổi quyền, thao tác trên site/rule/chứng chỉ, đổi gói, truy cập của back-office. Bảng audit\_logs **chỉ cho phép INSERT** (không UPDATE/DELETE); tùy chọn nối chuỗi băm để phát hiện sửa. Giữ tối thiểu 12 tháng (đề xuất).

# **7\. Độ tin cậy, sao lưu và mở rộng**

## ***7.1 Khi một thành phần hỏng***

| Thành phần | Ảnh hưởng tới khách | Ảnh hưởng tới edge | Cách xử lý |
| ----- | ----- | ----- | ----- |
| PostgreSQL | không đăng nhập, không sửa cấu hình, không thanh toán | edge vẫn chạy bằng snapshot cũ | failover sang replica, khôi phục theo thời điểm |
| Redis | chậm hơn, rate limit API giảm chính xác | không ảnh hưởng | hạ cấp: bỏ cache, đếm cục bộ |
| NATS | thông báo/log chậm | edge long-poll snapshot, đệm log ngắn hạn | khởi động lại cụm, phát lại |
| ClickHouse | dashboard analytics không xem được | log chờ trong hàng đợi | ingest dead-letter, phát lại sau |
| Object storage | không phát snapshot mới | giữ bản cũ | phục hồi hoặc bucket dự phòng |
| KMS | không ký snapshot, không cấp chứng chỉ mới | giữ bản cũ | không phát hành mới, cảnh báo |
| API/Worker | dashboard lỗi, job trễ | không ảnh hưởng | tự khởi động lại, job queue bền |

## ***7.2 Sao lưu và khôi phục***

* Postgres: base backup \+ WAL để khôi phục theo thời điểm (mục tiêu RPO khoảng 5 phút); **thử khôi phục hằng tuần** (job backup\_verify).  
* Snapshot trong object storage bật versioning; hạ tầng nằm trong Terraform nên dựng lại được.  
* ClickHouse: sao lưu định kỳ hoặc chấp nhận mất một phần analytics ở bản đầu (nhóm cần chốt).  
* Khôi phục thảm họa: bản sao lưu ở vùng khác; bản đầu chạy một vùng chính (ví dụ Singapore), không cần active-active vì edge hoạt động độc lập.

  ## ***7.3 Mở rộng***

* API và worker **stateless**, chạy nhiều bản và scale ngang; dùng PgBouncer để gom kết nối.  
* Phân vùng (partition) các bảng lớn như audit\_logs theo tháng; replica đọc cho truy vấn nặng.  
* NATS cụm 3 node khi lên production; ClickHouse tách riêng và shard khi cần.  
* Migration theo kiểu mở rộng rồi thu hẹp (expand/contract), tương thích ngược, không khóa bảng lâu.

# **8\. Quan sát và vận hành**

| Chỉ số mục tiêu (SLO) | Giá trị đề xuất |
| ----- | ----- |
| Khả dụng API | 99,9% |
| Thời gian từ lưu cấu hình đến khi edge áp dụng (p95) | dưới 30 giây |
| Độ trễ ingest log | dưới 60 giây |
| Gia hạn chứng chỉ thành công trước hạn | trên 99% |
| Xử lý webhook thanh toán | dưới 1 phút |

* **Metric** (Prometheus): độ trễ và lỗi API, độ sâu hàng đợi job, thời gian dựng snapshot, số edge theo trạng thái, tuổi snapshot theo edge, độ trễ ingest, lỗi webhook, số cảnh báo.  
* **Log** có cấu trúc (JSON), gắn request\_id và trace\_id, không chứa bí mật hoặc dữ liệu cá nhân thừa.  
* **Trace** bằng OpenTelemetry, bảng điều khiển Grafana, cảnh báo nội bộ qua Slack hoặc dịch vụ trực.  
* **Runbook** cho các sự cố điển hình: snapshot kẹt, cấp chứng chỉ hàng loạt thất bại, edge dao động, ingest chậm, webhook thanh toán lỗi, nghi lộ khóa.

# **9\. Kế hoạch kiểm thử**

| Tầng | Nội dung | Công cụ |
| ----- | ----- | ----- |
| Unit | can(), entitlement, máy trạng thái (site, subscription, edge), bao waf-core | go test |
| Tích hợp | DB, Redis, NATS, ClickHouse thật; **test RLS**: tenant A truy vấn dữ liệu tenant B phải rỗng | testcontainers |
| Contract | snapshot do control plane sinh ra được edge thật nạp được; schema log hai bên khớp | docker compose edge \+ control plane |
| E2E | đăng ký, thêm site, sửa rule, nâng gói, xem analytics | Playwright |
| Bảo mật | IDOR (đổi ID giữa hai tenant), XSS bằng payload trong log, SSRF qua origin, webhook giả, brute force | OWASP ZAP, script |
| Tải | CRUD API, ingest log | k6 |
| Chaos | tắt Postgres/Redis/NATS/KMS, snapshot hỏng, webhook trùng và đến muộn | script |
| Thanh toán | thất bại thẻ, hoàn tiền, webhook trễ, hết hạn gói | sandbox Stripe/PayOS |

**Chỉ số cho báo cáo**: thời gian từ lưu rule đến khi áp dụng trên toàn bộ edge, độ trễ API p95, thông lượng ingest, kết quả kiểm thử cô lập tenant.

# **10\. Triển khai và chi phí**

* **Môi trường**: dev (docker compose: Postgres, Redis, NATS, ClickHouse, MinIO, Mailhog, Stripe CLI), staging, production.  
* **Đóng gói**: Docker nhiều giai đoạn; migration chạy như một job riêng; cấu hình qua biến môi trường; bí mật lấy từ Secrets Manager.  
* **CI/CD** (GitHub Actions): lint → test → govulncheck → quét ảnh → build → triển khai staging → smoke test → triển khai production; dùng feature flag cho tính năng mới.  
* **Hạ tầng dưới dạng mã**: Terraform cho toàn bộ, tái dùng với module edge của data plane.

**Hạ tầng gần 0 đồng cho bản demo** (nối với mục 8.2 của tài liệu Data Plane)

* Phát triển: toàn bộ chạy local bằng docker compose.  
* Demo: **một VM** (dùng credit AWS hoặc Azure for Students) chạy API, worker, ingest, Postgres, Redis, NATS và ClickHouse (hoặc TimescaleDB), object storage bằng MinIO hoặc một bucket nhỏ; dashboard chạy cùng VM hoặc host tĩnh miễn phí. Gợi ý cấu hình khởi đầu khoảng 4 vCPU và 8 GB RAM (cần đo lại; ClickHouse khá tốn RAM nên cân nhắc TimescaleDB cho demo).  
* Email dùng Mailhog khi phát triển; Stripe dùng chế độ test.  
* **Cảnh báo**: gom mọi thứ vào một VM chỉ phù hợp demo; khi có khách thật phải tách Postgres/Redis/ClickHouse thành dịch vụ riêng hoặc managed và bật sao lưu.

# **11\. Danh sách kiểm tra hoàn thành (Definition of Done)**

* Đăng ký, xác minh email, đăng nhập, 2FA, xoay refresh token hoạt động; có test tái sử dụng token.  
* Ma trận RBAC được test đầy đủ; API key có scope.  
* RLS bật cho mọi bảng của tenant; test cô lập tenant đạt.  
* Thêm site, xác minh DNS, kiểm tra origin (chống SSRF) hoạt động.  
* Rule được kiểm tra bằng waf-core; có monitor mode, phiên bản và rollback.  
* Snapshot được ký, phát hành bằng canary, rollback được; site lỗi không làm hỏng cả vùng.  
* Edge đăng ký bằng token, nhận mTLS, gửi heartbeat; DNS tự thêm/rút.  
* Chứng chỉ cấp và gia hạn tự động; khóa riêng nằm trong KMS/Secrets Manager.  
* Ingest và analytics chạy; retention theo gói; mọi truy vấn có tenant\_id.  
* Thanh toán sandbox chạy đủ luồng; webhook idempotent; có đối soát.  
* Entitlement được kiểm tra ở API, snapshot builder và edge.  
* Cảnh báo email/Slack có chống nhiễu.  
* Audit log chỉ thêm; back-office có 2FA và impersonation ghi lại.  
* Sao lưu và khôi phục đã thử thành công ít nhất một lần.  
* Tải và chaos test đạt mục tiêu đã đặt (ghi số đo thực).

# **12\. Rủi ro và lưu ý**

1. **Phạm vi quá lớn** (auth, billing, dashboard, analytics): giảm bằng cách dùng bên thứ ba (Keycloak, Stripe) và cắt tính năng ở mục 15\.  
2. **Lệch schema giữa control plane và edge**: dùng chung waf-core và contract test.  
3. **Rò rỉ giữa tenant**: RLS, kiểm thử tự động, không dùng tài khoản DB có quyền bỏ qua RLS trong API.  
4. **Snapshot hỏng ảnh hưởng nhiều site**: cô lập lỗi theo site, canary, rollback.  
5. **Lộ khóa ký snapshot**: KMS, xoay khóa, kiểm tra ở edge, khả năng thu hồi.  
6. **ClickHouse tốn RAM và khó vận hành**: có phương án nhẹ (TimescaleDB) cho demo.  
7. **Hóa đơn và thuế tại Việt Nam, quyền riêng tư**: cần tư vấn chuyên môn, không tự kết luận.  
8. **Phụ thuộc bên thứ ba** (Stripe, SES, nhà cung cấp DNS/KMS): bọc sau interface (adapter) để thay được.  
9. **Credit miễn phí hết hạn**: lên kế hoạch thu gọn về một VM và bảo toàn dữ liệu.  
10. **SLA**: bảng gói ghi 99,99% cho Enterprise nhưng bản đầu chỉ nhắm 99,9% trên một vùng control plane; cần quyết định cách trình bày.

## **13\. Việc cần nhóm xác nhận trước khi code**

* Dùng Go (khuyến nghị, chung waf-core với edge) hay FastAPI (khi đó cần vb dịch vụ Go để kiểm tra DSL).  
* Tự làm auth hay dùng Keycloak.  
* Cổng thanh toán cho demo: chỉ Stripe test mode hay thêm PayOS/VNPay.  
* **Tên miền gốc (apex)**: dùng ALIAS/CNAME flattening ở phía khách hay cấp địa chỉ IP cố định (anycast hoặc bản ghi A) cho khách.  
* Số vùng đặt control plane (một vùng \+ sao lưu) và cách ghi SLA trong bảng gói.  
* ClickHouse hay TimescaleDB cho bản demo.  
* Phạm vi bản đầu: API công khai, export SIEM, back-office có đưa vào hay để sau.  
* Nhà cung cấp DNS có API để làm GeoDNS tự động.  
* Chính sách quyền riêng tư và điều khoản dịch vụ (cần tư vấn).

