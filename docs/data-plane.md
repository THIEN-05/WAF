# **Tài liệu kỹ thuật Data Plane** 

# **0\. Cách đọc tài liệu**

Tài liệu này gom toàn bộ nội dung cần chuẩn bị để xây **data plane**: các edge node nhận lưu lượng, kiểm tra, lọc rồi chuyển request sạch về máy chủ gốc (origin). Mỗi khâu được viết theo cùng một khuôn: **mục đích → đầu vào/đầu ra → các bước xử lý → cấu trúc dữ liệu/thuật toán → chế độ lỗi → cách kiểm thử**.

Lưu ý: tên thư viện chỉ là đề xuất và chưa ghim phiên bản (khi code hãy ghim phiên bản và kiểm tra giấy phép); mọi con số hiệu năng là **mục tiêu cần tự đo lại**, không phải cam kết.

# **1\. Mục tiêu, phạm vi và nguyên tắc**

## ***1.1 Data plane làm gì***

Khách hàng trỏ CNAME của website về hệ thống. Mọi request đi qua edge node để: kết thúc TLS → nhận diện website → kiểm tra/lọc → chuyển về origin → trả response → ghi log và số liệu. Control plane (dashboard, API, thanh toán) chỉ cấp cấu hình; edge không gọi database trên đường xử lý request.

## ***1.2 Yêu cầu chức năng***

* FR1: Kết thúc TLS, tự cấp và gia hạn chứng chỉ theo từng tên miền.  
* FR2: Định tuyến theo Host đến đúng website/gói dịch vụ/origin.  
* FR3: Chặn/cho phép theo IP, CIDR, quốc gia, ASN.  
* FR4: Giới hạn tốc độ (rate limit) theo nhiều khóa.  
* FR5: Rule engine tùy chỉnh với ngôn ngữ điều kiện (DSL).  
* FR6: WAF chuẩn (SQLi, XSS, path traversal, RCE, SSRF…) có chấm điểm bất thường.  
* FR7: Quản lý bot (chấm điểm, JS challenge, CAPTCHA, bot tốt được xác minh).  
* FR8: Chống DDoS tầng ứng dụng (L7) và chế độ “Under Attack”.  
* FR9: Cache (tùy gói), reverse proxy ổn định tới origin (pool, timeout, health check).  
* FR10: Ghi log sự kiện và số liệu bất đồng bộ, không làm chậm request.  
* FR11: Nhận cấu hình mới không cần khởi động lại (hot reload, last-known-good).  
* FR12: Áp dụng quota/tính năng theo gói (entitlement).

  ## ***1.3 Yêu cầu phi chức năng (mục tiêu ban đầu, cần đo lại)***

| Hạng mục | Mục tiêu đề xuất |
| ----- | ----- |
| Độ trễ cộng thêm của edge (không inspect body) | p99 dưới 5 ms |
| Độ trễ cộng thêm khi inspect body nhỏ | p99 dưới 10–15 ms |
| Thông lượng | vài nghìn request/giây trên 2 vCPU (đo bằng k6/wrk) |
| Bộ nhớ | dưới 1 GB cho vài trăm website |
| Khả dụng | mất control plane vẫn chạy bằng cấu hình cũ |
| Reload cấu hình | không rớt kết nối đang chạy |

  ## ***1.4 Nguyên tắc thiết kế***

1. **Rẻ trước, đắt sau**: kiểm tra IP/rate limit trước, quét body và regex sau.  
2. **Config là snapshot bất biến trong RAM**, thay bằng hoán đổi con trỏ nguyên tử.  
3. **Mọi quyết định đều có lý do**: ghi rule\_id, điểm số, hành động vào log.  
4. **Tài nguyên có giới hạn**: giới hạn kích thước header/body, thời gian xử lý, bộ nhớ bộ đếm.  
5. **Regex an toàn**: chỉ dùng RE2 (thư viện regexp của Go, thời gian tuyến tính) để tránh ReDoS.  
6. **Fail-open hay fail-close do cấu hình**: lỗi nội bộ WAF thì cho qua hay chặn là lựa chọn của từng site/gói.  
7. **Quan sát được**: metric, log, trace cho từng pha.

   ## ***1.5 Ngoài phạm vi***

DDoS tầng 3/4 (SYN flood, UDP flood, băng thông lớn) **không thể chặn bằng VM thường**; cần nhà cung cấp mạng/anycast có scrubbing. Data plane này chỉ xử lý L7. Khi trình bày đồ án, nên nêu rõ giới hạn này.

# **2\. Kiến trúc tổng thể của một edge node**

```
Internet ─► [Listener :80/:443] ─► [Pipeline xử lý request] ─► Origin
                 │                        │
          TLS / JA3 capture      Access → RateLimit → Rules → WAF → Bot → Cache → Proxy
                                          │
   Sidecar/goroutine: ConfigSync · CertManager · LogShipper · Metrics · GeoIP/Blocklist updater
```

## ***2.1 Các pha xử lý request***

| Pha | Tên | Chi phí | Có thể dừng sớm |
| :---: | ----- | :---: | ----- |
| P0 | Accept \+ TLS \+ lấy fingerprint | thấp | từ chối kết nối |
| P1 | Parse \+ định tuyến theo Host | rất thấp | 404/421 |
| P2 | Dựng RequestCtx | thấp | – |
| P3 | Kiểm tra trạng thái site \+ entitlement | rất thấp | 403/402 |
| P4 | Access control (IP/Geo/ASN, allow/block) \+ cổng Under Attack | thấp | block/challenge |
| P5 | Rate limit | thấp–vừa | 429 |
| P6 | Custom rules của khách | vừa | allow/block/challenge |
| P7 | Managed WAF (OWASP) | cao | block |
| P8 | Bot management | vừa | challenge/block |
| P9 | Cache lookup | thấp | trả từ cache |
| P10 | Reverse proxy tới origin | phụ thuộc mạng | 502/504 |
| P11 | Xử lý response (header, trang chặn) | thấp | – |
| P12 | Log \+ metric (bất đồng bộ) | thấp | – |

Thứ tự có thể điều chỉnh, nhưng giữ quy tắc: **allow-list của khách ở P4/P6 được phép bỏ qua các pha sau** (theo tùy chọn skip), và các pha nặng (P7) luôn đứng sau các pha nhẹ.

# **3\. Công nghệ và cấu trúc mã nguồn**

## ***3.1 Công nghệ đề xuất***

| Thành phần | Lựa chọn | Ghi chú |
| ----- | ----- | ----- |
| Ngôn ngữ | Go | goroutine, net/http, dễ triển khai nhiều vùng |
| HTTP server/proxy | net/http \+ httputil.ReverseProxy (tùy biến Transport) | đủ cho đồ án; fasthttp nhanh hơn nhưng hạn chế HTTP/2 |
| TLS/ACME | certmagic hoặc lego | cấp chứng chỉ Let’s Encrypt |
| GeoIP/ASN | MaxMind GeoLite2 (cần đăng ký miễn phí) hoặc DB-IP Lite | kiểm tra điều khoản giấy phép |
| Cây CIDR | thư viện radix/bart hoặc tự viết | tra cứu IP nhanh |
| Cache bộ nhớ | otter/ristretto hoặc LRU tự viết |  |
| Redis client | go-redis | bộ đếm rate limit phân tán |
| Hàng đợi log | NATS (hoặc Redis Streams) | nhẹ hơn Kafka |
| Metric | prometheus/client\_golang |  |
| Tìm chuỗi nhanh | Aho-Corasick | tiền lọc từ khóa trước khi chạy regex |
| Kiểm thử tải | k6, wrk |  |

## ***3.2 Cấu trúc repo gợi ý***

```
edge/
  cmd/edge/main.go            # khởi động, đọc cấu hình, graceful shutdown
  internal/
    listener/                 # TLS, JA3 capture, giới hạn kết nối
    router/                   # Host -> Site
    reqctx/                   # RequestCtx, Decision
    access/                   # IP/Geo/ASN, blocklist
    ratelimit/                # token bucket, sliding window, Redis
    rules/                    # lexer, parser, AST, compiler, evaluator
    waf/                      # normalizer, detectors, scoring, exclusions
    bot/                      # scoring, challenge, verified bots
    ddos/                     # baseline, under-attack state machine
    cache/                    # key, store, purge
    proxy/                    # transport, LB, health check, retry
    response/                 # block page, challenge page, header
    telemetry/                # log schema, shipper, metrics
    configsync/               # snapshot, verify, apply
    certs/                    # cert store, ACME
  rulesets/                   # managed rules (YAML)
  test/                       # corpus tấn công, corpus sạch, integration
  deploy/                     # Dockerfile, systemd, Terraform
```

# **4\. Mô hình cấu hình (Snapshot)**

## ***4.1 Nguyên tắc***

* Control plane đóng gói toàn bộ cấu hình dành cho một edge thành **snapshot có version** và chữ ký.  
* Edge tải snapshot, **kiểm tra chữ ký, biên dịch (regex, rule, CIDR), chạy kiểm tra hợp lệ**, rồi mới hoán đổi con trỏ (atomic pointer). Nếu lỗi thì giữ bản cũ và báo về control plane.  
* Lưu bản **last-known-good** xuống đĩa để khởi động lại khi mất kết nối control plane.

  ## ***4.2 Ví dụ nội dung snapshot (dạng YAML để dễ đọc)***

```
version: 1842
generated_at: 2026-11-19T08:00:00Z
global:
  blocklists_version: 311
  managed_ruleset: crs-lite-1.4
sites:
  - id: site_001
    tenant_id: t_100
    status: active
    plan: pro
    domains: [example.com, www.example.com]
    origins:
      - url: https://203.0.113.10
        weight: 1
        host_header: example.com
        tls_verify: true
    fail_mode: open
    waf: {mode: block, sensitivity: medium, body_limit_kb: 64, exclusions: []}
    access: {allow_ips: [], block_ips: [198.51.100.0/24], block_countries: [], block_asns: []}
    rate_limits:
      - id: rl_login
        match: http.path == '/login' and http.method == 'POST'
        key: ip
        limit: 10
        window_s: 60
        action: block
        ban_s: 600
    rules:
      - id: r_1
        priority: 10
        expr: http.path starts_with '/admin' and ip.geo.country != 'VN'
        action: block
    bot: {mode: challenge, threshold: 60}
    cache: {enabled: false}
    secrets: {challenge_hmac_key_id: k7}
```

  ## ***4.3 Chỉ mục dựng sẵn khi nạp snapshot***

* Bảng băm host → \*Site (khớp chính xác) và cây hậu tố cho wildcard.  
* Cây CIDR cho allow/block theo site và danh sách toàn cục.  
* Rule đã biên dịch thành cây hàm (closure), regex đã compile sẵn.  
* Cấu hình entitlement đã giải thành cờ nhanh (bool/số) trong Site.

  # **5\. Chi tiết từng khâu**

  ## ***5.1 Listener và TLS (P0)***

**Mục đích**: nhận kết nối an toàn, lấy thông tin phục vụ phát hiện bot, chống kết nối chậm/lạm dụng.

**Các bước**

1. Mở cổng :443 (TLS, ALPN h2 và http/1.1) và :80 (chuyển hướng sang HTTPS, đồng thời phục vụ HTTP-01 của ACME).  
2. Cấu hình tls.Config: tối thiểu TLS 1.2, bộ mã hóa hiện đại, xoay vòng khóa session ticket, OCSP stapling.  
3. Chọn chứng chỉ theo SNI trong GetCertificate: tra site theo SNI, lấy chứng chỉ từ cache RAM.  
4. Cấp chứng chỉ: **chỉ cấp cho tên miền đã xác minh** (khách thêm bản ghi TXT/CNAME) để tránh bị lạm dụng làm cạn hạn mức Let’s Encrypt. Đã chốt: control plane cấp và gia hạn chứng chỉ tập trung (certmagic hoặc lego chạy ở control plane), lưu khóa riêng trong KMS/Secrets Manager (xem 5.14) rồi đẩy chứng chỉ xuống edge qua kênh mTLS. Edge không tự gọi ACME. Nếu MVP cần đơn giản hơn, có thể tạm chạy certmagic trên edge với kho lưu trữ dùng chung, rồi chuyển về mô hình tập trung.  
5. **Lấy fingerprint TLS (JA3/JA4)**: thư viện chuẩn của Go không cung cấp thứ tự extension của ClientHello. Cách làm: bọc net.Conn, đọc trước (peek) bản ClientHello thô, tự phân tích và tính JA3/JA4, lưu theo kết nối rồi gắn vào RequestCtx qua ConnContext.  
6. Đặt timeout: ReadHeaderTimeout \~10 giây, IdleTimeout 60–120 giây, MaxHeaderBytes 32–64 KB; giới hạn số kết nối đồng thời trên mỗi IP bằng một wrapper của Listener (chống Slowloris).  
7. Nếu phía trước có load balancer L4 (ví dụ NLB), bật **PROXY protocol** để lấy IP thật; chỉ tin header chuyển tiếp từ các CIDR tin cậy.

**Chế độ lỗi**: không có chứng chỉ cho SNI → trả chứng chỉ mặc định và từ chối ở lớp HTTP; JA3 lỗi → để trống, bot scoring bỏ qua tín hiệu này.

**Kiểm thử**: sslyze/testssl.sh, kiểm tra ALPN, kiểm thử Slowloris bằng công cụ trong lab, kiểm tra gia hạn chứng chỉ sát hạn.

## ***5.2 Định tuyến theo Host (P1, P3)***

1. Chuẩn hóa Host: chữ thường, bỏ cổng, bỏ dấu chấm cuối, chuyển punycode.  
2. Tra host → Site: khớp chính xác trước, wildcard sau. Không thấy → trả 421/404 và **không tốn tài nguyên** cho các pha sau.  
3. Kiểm tra **SNI khác Host** (domain fronting): nếu lệch thì chặn và ghi log.  
4. Kiểm tra trạng thái site: active, suspended (hết hạn gói), pending (chưa xác minh DNS). Site bị khóa trả trang thông báo.  
5. Nạp entitlement của gói vào ngữ cảnh (số rule tối đa, có bot hay không, giới hạn body, thời gian giữ log…).

   ## ***5.3 RequestCtx và Decision (P2)***

RequestCtx gom mọi dữ kiện của request để các pha dùng chung, tính **lười** (lazy) cho phần đắt:

* Cố định: ID request, thời điểm, Site, IP thật, cổng, giao thức, JA3/JA4, phương thức, Host, đường dẫn, chuỗi truy vấn, header.  
* Tính khi cần: query đã phân tích, cookie, User-Agent đã phân tích, Geo/ASN (tra DB), body (đã giới hạn), các biến thể đã chuẩn hóa của từng mục tiêu quét.  
* Kết quả: Decision{Action, RuleID, Phase, Score, Tags, Reason}; hành động gồm allow, block, challenge, rate\_limited, log\_only.

Dùng sync.Pool để tái sử dụng đối tượng, giảm áp lực GC.

## ***5.4 Access control: IP, Geo, ASN (P4)***

**Thứ tự đánh giá**: allow IP của site → block IP của site → block theo quốc gia/ASN của site → danh sách chặn toàn cục (IP xấu, Tor nếu bật) → cổng Under Attack.

**Cấu trúc dữ liệu**

* Cây CIDR (radix) cho IPv4 và IPv6, tra cứu O(độ dài bit).  
* Bảng ban tạm thời trong RAM có TTL (IP bị cấm do vi phạm rate limit/bot), đồng bộ nhẹ qua Redis nếu có.  
* Geo/ASN: nạp file cơ sở dữ liệu ở dạng memory-map; tra cứu một lần mỗi request rồi lưu vào RequestCtx.

**Nguồn danh sách chặn toàn cục**: các danh sách công khai như Spamhaus DROP, FireHOL (kiểm tra điều khoản sử dụng), cập nhật 6–24 giờ một lần bởi control plane và phân phối cùng snapshot (chỉ số blocklists\_version).

**Phân tầng theo gói**: Free chỉ chặn IP/CIDR; Pro thêm quốc gia; Business thêm ASN; Enterprise thêm danh sách tùy chỉnh lớn và API.

**Lưu ý**: IP sau CDN/NAT dùng chung có thể gây chặn nhầm; luôn có cơ chế allow-list và ghi rõ lý do chặn trong log.

## ***5.5 Rate limiting (P5)***

**Chính sách** (mỗi site có nhiều chính sách): điều kiện áp dụng (biểu thức DSL), khóa đếm, hạn mức, cửa sổ thời gian, hành động (block/challenge/throttle), thời gian cấm.

**Khóa đếm hỗ trợ**: IP, IP+đường dẫn, header/cookie cụ thể, JA3, toàn site.

**Thuật toán**

* **Token bucket cục bộ** (nguyên tử, không khóa) cho giới hạn trên từng edge: rẻ nhất, dùng làm lớp đầu.  
* **Sliding window counter** để chính xác hơn: ước lượng \= đếm cửa sổ trước × (1 − phần đã trôi qua của cửa sổ hiện tại) \+ đếm cửa sổ hiện tại.  
* **Phân tán qua Redis** khi cần giới hạn toàn cầu: dùng INCR \+ PEXPIRE trong một script Lua để thao tác nguyên tử; đồng bộ theo lô bất đồng bộ để không thêm độ trễ cho mỗi request.

```
-- KEYS[1] = khóa đếm cho cửa sổ hiện tại, ARGV[1] = độ dài cửa sổ (ms)
local cur = redis.call('INCR', KEYS[1])
if cur == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[1]) end
return cur
```

**Bảo vệ chính bộ đếm**: bảng đếm chia shard, **băm khóa về kích thước cố định**, đặt trần số khóa và dọn theo TTL, tránh việc kẻ tấn công tạo hàng triệu khóa để làm cạn RAM.

**Phản hồi**: mã 429 kèm Retry-After; ghi log với rule\_id của chính sách.

**Kiểm thử**: unit test thuật toán với đồng hồ giả; test song song nhiều goroutine; k6 mô phỏng vượt hạn mức; kiểm tra hành vi khi Redis chết (mặc định hạ cấp về bộ đếm cục bộ).

**Chạy k6 cục bộ**: khởi chạy edge với snapshot có hạn mức thấp cho `POST /login`, rồi chạy `k6 run -e BASE_URL=http://127.0.0.1:8080 -e SITE_HOST=site.test test/k6/ratelimit.js`. Có thể đặt `VUS` và `DURATION` để đổi tải. Script chỉ gửi request tới `BASE_URL` do người vận hành chỉ định; không trỏ vào hệ thống bên thứ ba.

**MMDB GeoLite2 tùy chọn**: tạo tài khoản MaxMind, tải GeoLite2 Country và/hoặc GeoLite2 ASN theo điều khoản MaxMind, giải nén ngoài repository (ví dụ `D:/waf-data/GeoLite2-Country.mmdb`), rồi đặt `EDGE_GEOIP_COUNTRY_MMDB` và `EDGE_GEOIP_ASN_MMDB` tới các file đó. Không commit hoặc phân phối file dữ liệu. Test `TestMMDBFilesWhenOperatorDatabasesAreConfigured` tự skip khi không cấu hình hoặc file chưa được cấp.

## ***5.6 Rule engine và DSL (P6)***

**Mục đích**: cho khách tự viết điều kiện lọc, được biên dịch sẵn để chạy nhanh.

**Trường dữ liệu (fields)**: http.host, http.method, http.path, http.query, http.uri, http.user\_agent, http.referer, http.header\['tên'\], http.cookie\['tên'\], http.body (đã giới hạn), req.size, ip.src, ip.geo.country, ip.geo.asn, tls.ja3, bot.score, waf.score.

**Toán tử**: \==, \!=, \<, \>, contains, starts\_with, ends\_with, matches (RE2), in {...}, in\_cidr, and, or, not, ngoặc đơn. **Hàm**: lower(), url\_decode(), len().

**Hành động**: allow, block (kèm mã trạng thái, trang tùy chỉnh), challenge, log, rate\_limit(policy), tag, skip(pha).

**Văn phạm rút gọn (EBNF)**

```
expr     = or_expr ;
or_expr  = and_expr { 'or' and_expr } ;
and_expr = not_expr { 'and' not_expr } ;
not_expr = [ 'not' ] cmp ;
cmp      = operand [ op operand ] | '(' expr ')' ;
operand  = field | string | number | list | func '(' operand ')' ;
```

**Ví dụ**

```
http.path starts_with '/admin' and ip.geo.country != 'VN'
http.user_agent matches 'sqlmap|nikto|nmap'
http.method == 'POST' and http.path == '/login' and bot.score > 70
ip.src in_cidr {203.0.113.0/24, 198.51.100.0/24}
```

**Quy ước cú pháp**: chuỗi luôn dùng nháy đơn (ví dụ 'VN') và trường quốc gia luôn là ip.geo.country, không dùng ip.geo đơn lẻ. Bản idea cũ (Google Docs) đang dùng ip.geo và nháy kép, cần sửa lại cho khớp quy ước này.

**Các bước xây dựng**

1. **Lexer**: tách token (định danh, chuỗi, số, toán tử).  
2. **Parser**: đệ quy xuống hoặc Pratt, sinh cây cú pháp (AST).  
3. **Kiểm tra kiểu**: mỗi field có kiểu cố định; sai kiểu thì báo lỗi kèm dòng/cột.  
4. **Tối ưu**: gập hằng số, compile sẵn regex, sắp xếp vế rẻ (so sánh chuỗi/số) trước vế đắt (regex), ngắn mạch and/or.  
5. **Biên dịch** thành cây hàm func(\*RequestCtx) bool.  
6. **Đánh giá**: duyệt rule theo priority; gặp rule khớp thì thực thi hành động. Rule dùng http.body sẽ bật cờ để hệ thống chỉ đọc body khi thật sự cần.

**An toàn**: chỉ dùng RE2, giới hạn độ dài biểu thức, số rule và kích thước regex theo gói, kiểm tra cú pháp ngay ở control plane (API trả lỗi cụ thể), rule có thể đặt **chế độ chỉ ghi log** để thử trước khi chặn thật, và có thể đặt expires\_at.

**Kiểm thử**: unit test dạng bảng (biểu thức, request mẫu, kết quả mong đợi), fuzz parser, benchmark số rule/giây.

## ***5.7 Managed WAF – bộ luật chuẩn kiểu OWASP (P7)***

**Mục đích**: phát hiện các lớp tấn công phổ biến mà khách không cần tự viết rule.

**Bước 1 – Chọn mục tiêu quét**: đường dẫn, tên và giá trị tham số query, các header chọn lọc (User-Agent, Referer, Cookie, X-Forwarded-For, header tùy chỉnh), cookie, và **body** nếu Content-Type thuộc nhóm hỗ trợ (form, JSON, XML, multipart, text) và kích thước trong giới hạn của gói (gợi ý: Free 8 KB, Pro 64 KB, Business/Enterprise 128–256 KB; vượt thì chỉ quét phần đầu và gắn cờ).

Loader YAML hỗ trợ `path`, `args`, `body`, `cookies`, `headers` và `protocol`. Target `protocol` quét tín hiệu chuẩn hóa do edge dựng từ request (thiếu Host, method ngoài danh sách, Content-Length đi cùng Transfer-Encoding, Content-Length lặp), không lấy một chuỗi protocol tùy ý từ client.

**Bước 2 – Chuẩn hóa (normalize)** theo chuỗi biến đổi, vì kẻ tấn công thường mã hóa để né luật:

* Giải mã URL lặp tối đa 3 lần (phát hiện mã hóa kép là một tín hiệu đáng ngờ).  
* Giải mã thực thể HTML, loại bỏ byte NUL.  
* Chuẩn hóa đường dẫn (../, //, /./).  
* Chuyển chữ thường, nén khoảng trắng, loại bỏ comment SQL dạng /\* \*/.

**Bước 3 – Bộ phát hiện theo nhóm**

| Nhóm | Dấu hiệu chính (ví dụ) |
| ----- | ----- |
| SQL injection | tách token \+ so khớp mẫu; từ khóa như union select, sleep(, benchmark(, information\_schema, mẫu ' or 1=1 \-- |
| XSS | thẻ \<script, thuộc tính sự kiện kiểu onerror=, javascript:, data:text/html, svg onload |
| Path traversal / LFI | ../, %2e%2e, /etc/passwd, boot.ini, php://, file:// |
| RFI | URL ngoài trong tham số kiểu include/path |
| RCE / command injection | \`; |
| SSRF | địa chỉ nội bộ/metadata cloud (169.254.169.254, 127.0.0.1, dải 10.x/192.168.x) trong tham số |
| XXE | \<\!DOCTYPE, \<\!ENTITY |
| SSTI | mẫu như {{7\*7}}, \${7\*7} |
| Deserialization | dấu hiệu chuỗi serialize của Java/PHP |
| Bất thường giao thức | thiếu Host, phương thức lạ, vừa có Content-Length vừa Transfer-Encoding, Content-Length trùng lặp (request smuggling) |
| Scanner/công cụ dò | User-Agent như sqlmap, nikto, nmap, acunetix |
| Tệp nhạy cảm | .env, .git/, wp-config.php.bak, .aws/credentials |
| Virtual patching | mô-đun thêm nhanh luật cho CVE mới |

**Bước 4 – Chấm điểm bất thường (anomaly scoring)**: mỗi luật có mức nghiêm trọng (critical 5, error 4, warning 3, notice 2), cộng dồn thành waf.score. Quyết định theo độ nhạy của site (điểm khởi đầu để tinh chỉnh bằng bộ dữ liệu thử): Low ≥ 10, Medium ≥ 5, High ≥ 3\. Chế độ: monitor (chỉ ghi), challenge, block. Mỗi luật có **paranoia level 1–4**; gói cao mở thêm luật nghiêm ngặt.

**Bước 5 – Ngoại lệ (exclusions)**: khách có thể loại một rule\_id khỏi một đường dẫn/tham số cụ thể để xử lý chặn nhầm; có chế độ học (monitor) trước khi bật chặn.

**Hiệu năng**

* Tiền lọc bằng Aho-Corasick: chỉ chạy regex khi có từ khóa nghi ngờ.  
* Dừng sớm khi điểm đã vượt ngưỡng.  
* Ngân sách công việc xác định theo gói: Free 128 KiB/256 bước normalize/128 cửa sổ regex; Pro 256 KiB/512/192; Business 384 KiB/768/256; Enterprise 512 KiB/1.024/384. Đây là byte target đầu vào đã nhận xử lý, số normalize block và số candidate regex thực chạy; hết trần gắn `waf_scan_truncated`/`waf_work_exhausted` (body còn gắn `waf_body_truncated`) rồi áp fail-mode. `budget_ms` là cầu chì đồng hồ tường mặc định 100 ms, cấu hình tối đa 5.000 ms; khi số WAF in-flight vượt GOMAXPROCS, ngưỡng được nhân theo backlog ước lượng (tối đa 5 giây) để không tính thời gian scheduler chờ như một pha bị treo. Chỉ cầu chì sau hiệu chỉnh mới phát `waf_budget_exceeded`.
* Khi quá tải, edge ước lượng backlog runnable bằng `max(WAF in-flight − GOMAXPROCS, 0)`, theo dõi EWMA độ trễ pha và tỷ lệ fuse trong 64 request gần nhất. Mức 1 (backlog >0 hoặc EWMA ≥12 ms) bỏ luật paranoia >1; mức 2 (backlog ≥GOMAXPROCS hoặc EWMA ≥30 ms) còn giảm một nửa trần công việc; mức 3 chỉ khi tối thiểu 32 request gần nhất có tỷ lệ fuse ≥25% và backlog hiện tại đã thoát ngưỡng, khi đó áp fail-mode. Mỗi mức có counter, tag audit và log khi chuyển mức. Quá tải tự nó không được tính là lỗi fuse.
* Khi body vượt cap entitlement, WAF chỉ buffer và quét prefix tối đa cap (đọc thêm 1 byte để nhận biết vượt); **không đọc hay quét đuôi thực** vì phần dư được stream tới origin. Trong vùng thực sự đã buffer, các candidate regex có thể giữ đầu và cuối; điều này không có nghĩa là body tail đã được kiểm tra. Free mặc định fail-open vì vậy có thể bị né bằng padding vượt cap. Giảm thiểu: cộng điểm body truncated (mặc định 3), giới hạn Content-Length/body theo loại nội dung và rate-limit chặt hơn cho request body lớn; gói trả phí nên đặt fail-closed/challenge.

**Nguồn luật**: OWASP Core Rule Set là nguồn tham khảo tốt (kiểm tra giấy phép), nhưng viết bằng cú pháp SecRule và dùng một số tính năng regex mà RE2 không hỗ trợ, nên cần **chuyển đổi/viết lại thủ công** sang định dạng YAML của hệ thống. Coraza (WAF mã nguồn mở bằng Go, chạy được CRS) có thể dùng làm **chuẩn so sánh** để đo tỷ lệ phát hiện của engine tự viết.

**Định dạng luật ví dụ**

```
- id: waf-sqli-001
  phase: request
  targets: [args, body, cookies]
  transforms: [url_decode, lowercase, remove_sql_comments]
  pattern: 'union[[:space:]]+(all[[:space:]]+)?select'
  severity: critical
  paranoia: 1
  tags: [owasp-a03, sqli]
```

**Kiểm thử**: bộ mẫu tấn công tự viết ngắn và bộ lưu lượng sạch trong `test/corpus/waf`; đo TPR/FPR theo nhóm/paranoia với baseline đã ghi và trần FPR cấu hình được. So sánh Coraza/CRS là TODO riêng cần mạng; mọi thử nghiệm công cụ chỉ chạy trên DVWA/lab của nhóm.

## ***5.8 Bot management (P8)***

**Mục đích**: phân biệt người và bot, chặn bot xấu, cho phép bot tốt.

**Điểm bot bot.score (0 \= giống người, 100 \= giống bot)**, cộng từ các tín hiệu:

* User-Agent: rỗng, thư viện HTTP (curl, python-requests, Go-http-client, scrapy), dấu hiệu headless.  
* Tính hợp lý của header: thiếu Accept/Accept-Language, thứ tự header không khớp trình duyệt tự nhận.  
* **Lệch fingerprint**: tự nhận Chrome nhưng JA3/JA4 giống curl/python.  
* Uy tín IP: ASN trung tâm dữ liệu, Tor, nằm trong danh sách chặn.  
* Hành vi: tốc độ request, tỷ lệ 404, quét đường dẫn tuần tự, không bao giờ tải tài nguyên tĩnh, không giữ cookie.  
* Kết quả thử thách trước đó: vượt challenge thì hạ điểm.

**Bot tốt đã xác minh**: Googlebot, Bingbot… được xác minh bằng reverse DNS rồi forward DNS (hoặc dải IP do hãng công bố), kết quả lưu cache; bot đã xác minh được cho qua và gắn nhãn verified\_bot.

**Thiết kế JS challenge**

1. Khi điểm vượt ngưỡng, trả trang thử thách chứa đoạn JS nhỏ.  
2. JS giải **proof-of-work** (tìm nonce để SHA-256 có tiền tố số 0, độ khó điều chỉnh được) và thu một số tín hiệu trình duyệt đơn giản.  
3. Gửi kết quả tới đường dẫn dành riêng (ví dụ /\_\_waf/verify).  
4. Edge kiểm tra PoW và tín hiệu, rồi đặt cookie đã ký: nội dung (site, hash User-Agent, /24 IPv4 hoặc /64 IPv6, hạn dùng) + **HMAC-SHA256** bằng khóa riêng của site (có xoay khóa).
5. Các request sau mang cookie; **bất kỳ edge nào cũng kiểm tra được** nhờ cùng keyring. Snapshot chỉ mang `challenge_hmac_key_id`; khóa bí mật được chuyển riêng qua mTLS theo hợp đồng `docs/control-plane.md` §2.3, không đặt khóa rõ trong snapshot. Hiệu lực khoảng 30 phút; giữ key ID cũ tới khi cookie cuối cùng hết hạn.

**Phân tầng theo gói**: Free không có; Pro có JS challenge; Business thêm CAPTCHA (dịch vụ bên thứ ba như Turnstile/hCaptcha, edge gọi API xác minh); Enterprise thêm mô hình tùy chỉnh.

**Giới hạn cần nói rõ**: JS challenge chỉ làm tăng chi phí cho bot đơn giản, **không chặn được** bot nâng cao chạy trình duyệt thật. Đừng cam kết tỷ lệ chặn tuyệt đối khi báo cáo.

**Mô hình ML (giai đoạn sau)**: huấn luyện ngoại tuyến (Python) từ log đã gán nhãn, bắt đầu bằng hồi quy logistic; xuất trọng số vào snapshot để edge tính điểm bằng phép nhân vector rất rẻ.

## ***5.9 Chống DDoS L7 và chế độ Under Attack***

**Mục đích**: giữ origin sống khi bị dồn request ở tầng ứng dụng và tự động siết bảo vệ khi có đột biến.

**Các bước**

1. **Đo đường cơ sở (baseline)** cho từng site: RPS trung bình động (EWMA, hệ số làm mượt khoảng 0,1) cùng độ lệch; thêm chỉ số tỷ lệ lỗi và độ trễ của origin.  
2. **Điều kiện kích hoạt**: RPS hiện tại vượt max(ngưỡng sàn, baseline × k) trong ít nhất vài giây, hoặc origin bắt đầu chậm/lỗi hàng loạt.  
3. **Máy trạng thái** (có độ trễ hysteresis để không nhảy qua lại):  
   * Normal → Elevated: tăng trọng số bot score, siết rate limit.  
   * Elevated → Under Attack: thử thách mọi request chưa có cookie hợp lệ, chặn nguồn có điểm cao.  
   * Under Attack → Cooldown → Normal: chỉ hạ khi RPS dưới ngưỡng liên tục vài phút.  
4. Khách có thể bật/tắt thủ công chế độ Under Attack từ dashboard (đẩy qua kênh khẩn, xem 5.14).  
5. **Đếm gộp**: theo IP, theo dải /24 và theo ASN để phát hiện tấn công phân tán.  
6. **Bảo vệ origin**: giới hạn số kết nối/request đồng thời tới mỗi origin (semaphore \+ hàng đợi ngắn); quá tải thì trả 503 kèm Retry-After thay vì dồn tiếp; nếu có cache thì phục vụ bản cũ (serve stale).  
7. **Giới hạn giao thức**: timeout đọc header/body, kích thước body tối đa, giới hạn số stream đồng thời của HTTP/2 (phòng các kiểu tấn công lạm dụng HTTP/2), giữ phiên bản Go được vá.

**Phân tầng**: Free chỉ có giới hạn cơ bản; Pro trở lên có chế độ tự động; Enterprise có ngưỡng tùy chỉnh.

**Giới hạn cần nói rõ**: chỉ xử lý được tấn công L7 trong khả năng của edge; tấn công thể tích lớn cần nhà cung cấp có scrubbing (xem mục 1.5).

**Kiểm thử**: dùng k6/vegeta **chỉ trên hạ tầng của nhóm**; kiểm tra chuyển trạng thái đúng và quay về bình thường, origin giả vẫn trả lời được trong lúc bị tấn công.

## ***5.10 Cache tại edge (P9)***

**Mục đích**: giảm tải origin và tăng tốc, theo gói.

**Phạm vi**: bản đầu chỉ có cache độc lập trên từng edge (mỗi edge tự lưu và tự phục vụ). **Chưa có CDN nhiều tầng**: không có tiered cache/origin shield và không đẩy nội dung chủ động giữa các edge. Vì vậy bảng gói nên ghi là “Cache” thay vì “Cache/CDN”; nếu nhóm muốn đủ CDN thì thêm tầng cache trung gian ở giai đoạn sau.

* **Khóa cache**: scheme \+ host \+ đường dẫn \+ query đã sắp xếp (tùy chọn bỏ tham số theo dõi như utm\_\*) \+ các header trong Vary.  
* **Điều kiện lưu**: chỉ GET/HEAD; trạng thái 200, 301, 404…; **không lưu** nếu có Set-Cookie, request có Authorization, hoặc Cache-Control là private/no-store.  
* **TTL**: lấy từ s-maxage/max-age, cho phép site ghi đè và đặt giới hạn tối thiểu/tối đa.  
* **Kho lưu**: LRU trong RAM cho đối tượng nhỏ (ví dụ dưới 1 MB), tùy chọn lưu đĩa; hạn mức dung lượng theo gói.  
* **Chống bão cache (stampede)**: gộp các request cùng khóa bằng singleflight; hỗ trợ stale-while-revalidate.  
* **Purge**: theo URL, tiền tố hoặc tag; control plane phát lệnh tới mọi edge.  
* **An toàn**: chuẩn hóa khóa và không để header ngoài khóa ảnh hưởng nội dung được lưu (tránh cache poisoning); thêm header X-Cache: HIT/MISS.  
* MVP: bỏ qua Range request (chuyển thẳng tới origin).

  ## ***5.11 Reverse proxy tới origin (P10)***

**Transport theo từng nhóm origin** (giá trị khởi đầu, tinh chỉnh khi đo): giữ kết nối nhàn rỗi (khoảng 100/host, 90 giây), timeout kết nối 5 giây, timeout bắt tay TLS 5 giây, timeout chờ header phản hồi 30 giây (theo gói), bật HTTP/2 tới origin khi có thể.

**Xử lý header**

* Xóa header hop-by-hop và **xóa header do client tự gửi** có thể giả mạo (X-Forwarded-\*, X-Real-IP), rồi đặt lại: X-Forwarded-For (IP thật), X-Forwarded-Proto, Via, X-Request-ID.  
* Host gửi tới origin: giữ nguyên Host gốc hoặc đặt theo host\_header của site.

**Cân bằng tải và chịu lỗi**

* Thuật toán: round-robin có trọng số hoặc ít kết nối nhất.  
* Health check chủ động (ví dụ 10 giây/lần) và thụ động: **circuit breaker** (5 lỗi liên tiếp thì mở 30 giây, sau đó thử lại half-open).  
* Retry tối đa 1–2 lần, **chỉ** với GET/HEAD và lỗi kết nối (không retry khi đã gửi body).  
* Hỗ trợ WebSocket/upgrade và phản hồi dạng stream (SSE) bằng cách xả buffer liên tục.

**TLS tới origin**: chế độ off, full (không xác minh chứng chỉ), full\_strict (xác minh); mTLS tùy chọn cho Enterprise. Khuyến nghị khách chỉ cho phép IP của edge truy cập origin, hoặc dùng một header bí mật X-Origin-Auth.

**Chống lạm dụng làm proxy mở / SSRF**

* Khi khách thêm origin: phân giải DNS và **từ chối** IP loopback, dải riêng (10.x, 172.16–31.x, 192.168.x), link-local và địa chỉ metadata cloud.  
* **Kiểm tra lại ngay lúc kết nối** (hook dial) để chống DNS rebinding.  
* Phát hiện vòng lặp (origin trỏ về chính hệ thống) bằng header Via/đếm số lần chuyển tiếp.

**Buffer body cho WAF**: khi cần quét body thì đọc tối đa giới hạn vào bộ đệm rồi phát lại cho origin; phần vượt giới hạn truyền thẳng (stream).

**Lỗi**: 502 khi không kết nối được, 504 khi hết thời gian; trả trang lỗi có Request ID.

## ***5.12 Xử lý response (P11)***

* Thêm header an toàn theo cấu hình của khách (HSTS, X-Content-Type-Options…), tùy chọn xóa Server/X-Powered-By.  
* **Trang chặn** và **trang challenge** có Request ID để khách báo lại cho bộ phận hỗ trợ; không lộ chi tiết rule.  
* Nén phản hồi (gzip/brotli) nếu origin chưa nén và client hỗ trợ.  
* Ghi lại trạng thái, số byte, thời gian phản hồi của origin cho pha log.

  ## ***5.13 Logging và telemetry (P12)***

**Sự kiện log (schema đề xuất)**: ts, request\_id, site\_id, tenant\_id, edge\_id, region, client\_ip, country, asn, ja3, method, host, path, status, bytes\_in, bytes\_out, latency\_ms, upstream\_ms, action, rule\_id, waf\_score, bot\_score, cache\_status, tags.

**Quyền riêng tư**: không ghi body; không ghi giá trị Authorization/Cookie; che (redact) tham số nhạy cảm như password, token; cho phép che một phần IP theo cấu hình. Vì IP là dữ liệu cá nhân ở nhiều khu vực, cần chính sách quyền riêng tư và điều khoản xử lý dữ liệu.

**Luồng ghi**

1. Mỗi request đẩy sự kiện vào **channel/ring buffer không chặn**; đầy thì bỏ sự kiện và tăng bộ đếm log\_dropped (không bao giờ làm chậm request).  
2. Worker gom lô theo 1 giây hoặc 1.000 sự kiện, nén (gzip/zstd) rồi gửi qua NATS hoặc HTTP tới dịch vụ ingest, ghi vào ClickHouse.  
3. **Lấy mẫu**: 100% sự kiện bảo mật (bị chặn, challenge, rate limit); request bình thường lấy mẫu theo gói. Đồng thời tính **bộ đếm tổng hợp theo site theo phút** ngay trên edge để biểu đồ không bị ảnh hưởng bởi lấy mẫu event; khi queue đầy, delta bị drop và `log_dropped` phản ánh sai số có thể có.

**Metric Prometheus**: tổng request, histogram độ trễ **theo từng pha**, số lần chặn theo nhóm luật, số lần rate limit, tỷ lệ cache hit, lỗi origin, version snapshot, tuổi snapshot, goroutine/bộ nhớ. **Lưu ý cardinality**: không dùng site\_id làm label cho metric toàn cục nếu có hàng nghìn site; chi tiết theo site để ở log/ClickHouse.

**Trace**: OpenTelemetry với tỷ lệ lấy mẫu thấp (khoảng 0,1%) để điều tra độ trễ.

**Triển khai edge hiện tại**: dùng `prometheus/client_golang`; NATS batch mặc định ở `nats://127.0.0.1:4222`, subject `edge.logs.v1`, hoặc đặt `EDGE_INGEST_URL` để gửi HTTPS. Event batch JSON được nén zstd, tối đa 1 giây/1.000 bản ghi/512 KiB; queue mặc định 4.096 record, không có spool bền vững khi process dừng hoặc ingest lỗi. Request thường lấy mẫu Free 1%, Pro 10%, Business 50%, Enterprise 100%; sự kiện bảo mật luôn được chọn. Client IP mặc định mask IPv4 `/24`, IPv6 `/56`, điều chỉnh qua `EDGE_LOG_IP_MASK_V4_BITS` và `EDGE_LOG_IP_MASK_V6_BITS`. OpenTelemetry OTLP/HTTP chỉ export khi đặt `OTEL_EXPORTER_OTLP_ENDPOINT`. Cache response chưa được nối vào request pipeline nên cache-hit metric hiện chưa tăng.

## ***5.14 Đồng bộ cấu hình – ConfigSync***

**Đăng ký**: edge xác thực với control plane bằng mTLS hoặc token (edge\_id, vùng, version hiện tại).

**Nhận snapshot**

1. Nhận thông báo config.updated (NATS) hoặc long-poll GET /v1/snapshot?since=1842 kèm ETag.  
2. Tải snapshot (MVP: bản đầy đủ nén gzip; sau này thêm delta).  
3. **Xác minh chữ ký Ed25519** (control plane giữ khóa riêng, edge giữ khóa công khai) → phân tích → kiểm tra hợp lệ → biên dịch rule/regex → **hoán đổi con trỏ nguyên tử**.  
4. Ghi bản **last-known-good** ra đĩa (ghi file tạm rồi đổi tên để tránh hỏng giữa chừng).  
5. Báo version đang chạy về control plane.

**Triển khai an toàn**: phát canary theo vùng trước, giám sát tỷ lệ lỗi/chặn, rồi mới mở rộng; có cơ chế **rollback** về version trước.

**Khi sự cố**: control plane chết → edge giữ bản đang chạy; đo snapshot\_age và cảnh báo nếu quá lâu (ví dụ trên 1 giờ).

**Bí mật** (khóa HMAC challenge, thông tin xác thực origin): mã hóa riêng cho từng edge hoặc lấy qua kênh riêng, không để dạng rõ trong snapshot chung.

**Quản lý khóa (KMS/Secrets Manager)**: khóa riêng TLS, khóa ký snapshot (Ed25519), khóa HMAC của challenge và thông tin xác thực origin được lưu trong dịch vụ quản lý khóa của nhà cung cấp (AWS KMS \+ Secrets Manager, hoặc Azure Key Vault); nếu edge chạy trên nhiều nhà cung cấp, control plane là kho trung tâm và cấp bí mật qua mTLS để không phụ thuộc KMS riêng của từng cloud. Edge xin bí mật lúc khởi động bằng định danh riêng (IAM role, managed identity hoặc token ngắn hạn), giữ trong RAM và không ghi dạng rõ ra đĩa. Có quy trình xoay khóa (chứng chỉ, HMAC, khóa ký) và ghi audit log mọi lần truy cập bí mật.

**Kênh khẩn (override động)**: ban IP tức thời, purge cache, bật/tắt Under Attack đẩy qua NATS để có hiệu lực trong vài giây, không chờ snapshot đầy đủ.

### **5.15 Entitlement – áp dụng quota theo gói**

* **Khi tạo snapshot** (control plane): từ chối hoặc cắt các cấu hình vượt gói (số rule, số chính sách rate limit, giới hạn body, tính năng bot…).  
* **Khi chạy** (edge): bỏ qua tính năng không thuộc gói, phòng trường hợp hạ gói mà snapshot chưa kịp cập nhật.  
* **Đo mức dùng**: số request, băng thông, số rule theo tháng. Khi vượt hạn mức nên **hạ tính năng và cảnh báo**, không chặn lưu lượng hợp lệ của khách một cách đột ngột.

**Bảng quota theo gói (cần nhóm chốt giá trị)**

| Hạng mục | Free | Pro | Business | Enterprise |
| ----- | ----- | ----- | ----- | ----- |
| Custom rule (tối đa) | 3 | 20 | 100 | không giới hạn |
| Chính sách rate limit (tối đa) | 1 | 5 | 20 | 100 |
| Quét body WAF (KB) | 8 | 64 | 128 | 256 |
| Chặn theo | IP | IP \+ quốc gia | IP \+ quốc gia \+ ASN | thêm danh sách tùy chỉnh lớn |
| Bot | không | JS challenge | thêm CAPTCHA | tùy chỉnh (ML) |
| Under Attack | giới hạn cơ bản | tự động | tự động | ngưỡng tùy chỉnh |
| Cache | không | có | có | có |
| Giữ log | 24 giờ | 7 ngày | 30 ngày | 90 ngày \+ SIEM |
| Lấy mẫu log request bình thường | 1% | 10% | 50% | 100% |

Các dòng custom rule, chặn theo vị trí, bot, cache và thời gian giữ log lấy từ bản idea. Các dòng còn lại (số chính sách rate limit, giới hạn body, Under Attack, lấy mẫu log) là **đề xuất** của tài liệu này, cần nhóm xác nhận.

## ***5.16 Vòng đời tiến trình***

* **Khởi động**: nạp last-known-good → kết nối control plane → nạp chứng chỉ → chỉ mở listener khi đã sẵn sàng.  
* **Endpoint nội bộ**: /healthz (còn sống) và /readyz (sẵn sàng nhận lưu lượng); cổng metrics/admin chỉ mở trên giao diện riêng, không công khai.  
* **Tắt êm (graceful)**: nhận SIGTERM → đặt readyz thất bại → ngừng nhận kết nối mới → chờ kết nối cũ xong (tối đa khoảng 30 giây) → xả hết buffer log.  
* **Cập nhật không gián đoạn**: rút edge khỏi DNS/load balancer trước (drain), hoặc dùng systemd socket activation/SO\_REUSEPORT.  
* **Phục hồi lỗi (panic)**: bọc handler bằng recover, áp dụng fail\_mode của site và ghi log lỗi.  
* **Tối ưu hệ điều hành**: nâng giới hạn file mở (ulimit), chỉnh somaxconn, tcp\_max\_syn\_backlog, dải cổng cục bộ; đặt GOMAXPROCS/GOMEMLIMIT phù hợp container; đồng bộ giờ (chrony) vì hạn cookie và chứng chỉ phụ thuộc giờ hệ thống.

  # **6\. Khung mã Go (xương sống để bắt đầu code)**

Các đoạn dưới đây là **phác thảo cấu trúc**, chưa phải mã chạy hoàn chỉnh; mục đích là chốt ranh giới giữa các module.

## ***6.1 Pipeline và Decision***

```go
type Action int
const (
    ActionAllow Action = iota
    ActionBlock
    ActionChallenge
    ActionRateLimited
    ActionLogOnly
)

type Decision struct {
    Action Action
    RuleID string
    Phase  string
    Score  int
    Tags   []string
    Reason string
}
func (d Decision) Terminal() bool {
    return d.Action == ActionBlock || d.Action == ActionChallenge || d.Action == ActionRateLimited
}

type Phase interface {
    Name() string
    Handle(c *reqctx.RequestCtx) Decision
}

type Pipeline struct{ phases []Phase }

func (p *Pipeline) Run(c *reqctx.RequestCtx) Decision {
    for _, ph := range p.phases {
        start := time.Now()
        d := ph.Handle(c)
        metrics.ObservePhase(ph.Name(), time.Since(start))
        if d.Terminal() {
            return d
        }
    }
    return Decision{Action: ActionAllow}
}
```

## ***6.2 Giữ snapshot bằng con trỏ nguyên tử***

```go
type Holder struct{ p atomic.Pointer[Snapshot] }

func (h *Holder) Load() *Snapshot { return h.p.Load() }

func (h *Holder) Apply(raw []byte) error {
    s, err := ParseVerifyCompile(raw) // xác minh chữ ký, validate, compile rule/regex
    if err != nil {
        return err // giữ nguyên bản đang chạy
    }
    h.p.Store(s)
    return PersistLastKnownGood(raw)
}
```

## ***6.3 Handler chính***

```go
func (e *Edge) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    snap := e.holder.Load() // lấy snapshot một lần, dùng xuyên suốt request
    c := reqctx.New(r, snap)
    defer reqctx.Release(c)
    defer func() {
        if rec := recover(); rec != nil {
            e.onPanic(c, w, rec) // áp dụng fail_mode của site
        }
    }()

    site := snap.RouteHost(c.Host)
    if site == nil {
        http.Error(w, `unknown host`, 421)
        return
    }
    c.Site = site

    d := e.pipeline.Run(c)
    if d.Action != ActionAllow && d.Action != ActionLogOnly {
        e.respond(w, c, d) // trang chặn / challenge / 429
        e.logEvent(c, d)
        return
    }
    if e.cache.TryServe(w, c) {
        e.logEvent(c, d)
        return
    }
    e.proxy.Serve(w, c) // reverse proxy, ghi lại status và số byte
    e.logEvent(c, d)
}
```

## ***6.4 Biên dịch rule từ DSL***

```go
type Rule struct {
    ID       string
    Priority int
    Match    func(*reqctx.RequestCtx) bool // đã biên dịch từ DSL
    Action   Action
}

func Compile(expr string) (func(*reqctx.RequestCtx) bool, error) {
    toks, err := Lex(expr)
    if err != nil {
        return nil, err
    }
    ast, err := Parse(toks)
    if err != nil {
        return nil, err
    }
    if err := TypeCheck(ast); err != nil {
        return nil, err
    }
    ast = Optimize(ast) // gấp hằng số, precompile regex, đưa vế rẻ lên trước
    return Codegen(ast), nil // cây closure
}
```

## ***6.5 Rate limiter cục bộ (ý tưởng)***

```go
type bucket struct {
    tokens atomic.Int64 // micro-token để tránh số thực
    last   atomic.Int64 // thời điểm nạp gần nhất (ns)
}
// Allow: tính lượng token cần nạp theo thời gian đã trôi qua,
// cộng vào (tối đa bằng dung lượng), rồi trừ 1 token bằng CAS.
// Bảng bucket chia shard, khóa đã băm, có trần số phần tử và dọn theo TTL.
```

# **7\. Kế hoạch kiểm thử**

| Tầng | Nội dung | Công cụ | Tiêu chí đạt |
| ----- | ----- | ----- | ----- |
| Unit | lexer/parser/rule, chuẩn hóa, từng luật WAF, token bucket, cookie HMAC | go test, fuzz | độ phủ lõi trên 80% (mục tiêu) |
| Bộ mẫu tấn công | SQLi, XSS, traversal, RCE, SSRF, XXE, SSTI (chạy trong lab) | script \+ PayloadsAllTheThings | tỷ lệ phát hiện (TPR) đo được và báo cáo |
| Bộ mẫu sạch | lưu lượng thật/giả lập của ứng dụng hợp lệ (form, JSON, tìm kiếm có dấu nháy) | script, bản ghi từ site thử | tỷ lệ chặn nhầm (FPR) thấp, ghi số cụ thể |
| Tích hợp | edge \+ DVWA \+ origin giả bằng Docker Compose | ZAP, sqlmap, nikto (trên hệ thống của nhóm) | trước/sau khi bật WAF khác biệt rõ |
| Bảo mật cho chính edge | fuzz parser header, request smuggling, HTTP/2, header khổng lồ, body lỗi | công cụ fuzz, kiểm thử thủ công | không crash, không rò rỉ bộ nhớ |
| Tải | baseline, spike, origin chậm, body lớn, nhiều site | k6, wrk | độ trễ cộng thêm, req/s, bộ nhớ ổn định |
| Chaos | tắt control plane, tắt Redis, snapshot hỏng, chứng chỉ hết hạn, origin chết | script | edge vẫn chạy đúng fail\_mode |

**Chỉ số cần đưa vào báo cáo**: độ trễ khi đi qua edge so với gọi thẳng origin, thông lượng tối đa trên cấu hình nhỏ nhất, TPR/FPR của WAF và so sánh với Coraza+CRS, thời gian áp dụng cấu hình mới trên toàn bộ edge.

**Lưu ý đạo đức/pháp lý**: chỉ thử tấn công trên hệ thống do nhóm sở hữu hoặc môi trường lab riêng.

# **8\. Triển khai edge node**

* **Đóng gói**: Dockerfile nhiều giai đoạn, ảnh cuối tối giản (ví dụ distroless), chạy bằng user không phải root, cấp quyền bind cổng thấp bằng capability NET\_BIND\_SERVICE.  
* **Mạng/tường lửa**: mở 80/443 công khai; cổng metrics/admin chỉ trong mạng riêng; SSH giới hạn theo IP; chỉ cho phép edge kết nối tới control plane qua kênh có xác thực.  
* **Cấu hình khởi động** (biến môi trường): EDGE\_ID, REGION, địa chỉ control plane, khóa công khai kiểm tra snapshot, thư mục dữ liệu (certs, last-known-good, GeoIP).  
* **Hạ tầng dưới dạng mã**: một module Terraform edge\_node dùng lại cho mọi vùng và mọi nhà cung cấp.  
* **CI/CD** (GitHub Actions): build → test → lint (golangci-lint) → quét lỗ hổng (govulncheck, quét ảnh container) → đẩy ảnh → triển khai canary một vùng → mở rộng.  
* **Định tuyến người dùng tới edge**: GeoDNS/latency routing kèm health check (xem phần kiến trúc chung).  
* **Cập nhật dữ liệu ngoài**: GeoIP/ASN, danh sách chặn, bộ luật WAF cập nhật theo lịch từ control plane, có kiểm tra tính toàn vẹn.  
* **Giám sát và cảnh báo**: edge down, snapshot cũ, tỷ lệ 5xx tăng, tỷ lệ chặn bất thường, log\_dropped tăng, chứng chỉ sắp hết hạn, credit cloud sắp hết.

  ## ***8.1 Tự động hóa vòng đời edge (tự thiết kế)***

Mục tiêu: thêm hoặc gỡ một edge mà không phải cấu hình tay từng bước. Đây là phần nhóm tự thiết kế (xem bảng tự làm/bên thứ ba ở bản idea).

1. **Tạo**: Terraform/cloud-init dựng VM, kéo ảnh container; control plane phát một **token đăng ký dùng một lần** có hạn.  
2. **Tự đăng ký**: edge khởi động, gọi API đăng ký bằng token, nhận chứng chỉ mTLS ngắn hạn làm định danh, rồi tải snapshot, chứng chỉ TLS và bí mật cần thiết.  
3. **Tự kiểm tra**: edge chạy self-test (gọi một site thử nội bộ qua toàn bộ pipeline) rồi báo ready.  
4. **Vào dịch vụ**: sau vài lần health check liên tiếp đạt, control plane thêm edge vào GeoDNS/latency routing qua API của nhà cung cấp DNS.  
5. **Giám sát**: edge gửi heartbeat (version snapshot, tải, tỷ lệ lỗi); mất heartbeat quá ngưỡng thì control plane tự rút khỏi DNS.  
6. **Cập nhật**: canary một vùng, sau đó drain từng edge (readyz thất bại, rút DNS, chờ kết nối cũ xong), thay ảnh rồi cho quay lại.  
7. **Gỡ**: lệnh decommission → drain → rút DNS → thu hồi chứng chỉ mTLS và token → hủy tài nguyên bằng Terraform.  
8. **Mở rộng**: ngưỡng CPU/RPS kích hoạt thêm edge cùng vùng (bản đầu để bán tự động: control plane đề xuất, người duyệt).

Bản MVP: bước 1 và 7 làm bằng Terraform thủ công; các bước 2–5 tự động.

## ***8.2 Nhà cung cấp, credit và chi phí***

Số liệu tổng hợp ngày 19/11/2026 từ kết quả tìm kiếm, chưa mở kiểm tra từng trang; ưu đãi thay đổi thường xuyên nên hãy xác minh lại trước khi dùng: [AWS Free Tier FAQ](https://aws.amazon.com/free/faqs/), [GitHub Student Developer Pack](https://education.github.com/pack), trang Azure for Students.

| Nhà cung cấp | Ưu đãi | Gợi ý dùng | Lưu ý |
| ----- | ----- | ----- | ----- |
| AWS | Tài khoản mới: gói Free, tối đa 200 USD credit trong 6 tháng | control plane hoặc 1–2 edge (Tokyo, Frankfurt) | Hết 6 tháng hoặc hết credit thì tài khoản bị đóng; NAT Gateway, IP công cộng, băng thông ra vẫn tốn credit |
| Azure for Students | Khoảng 100 USD credit, không cần thẻ tín dụng, sinh viên từ 18 tuổi | control plane hoặc edge Đông Nam Á | Cần xác minh email sinh viên |
| Oracle Cloud Always Free | VM Arm đã giảm còn 2 OCPU/12 GB; có thể hết tài nguyên ở một số vùng | edge phụ, thử nghiệm | Không dùng cho thành phần quan trọng |
| GitHub Student Pack | Tên miền .me 1 năm, credit Heroku, GitHub Pro | tên miền, CI/CD, dashboard | Ưu đãi hay đổi (DigitalOcean có thể đã rời gói); nhận từng ưu đãi riêng |

* Đặt **budget alert** ở từng nhà cung cấp ngay ngày đầu.  
* Tắt hoặc xóa tài nguyên sau mỗi buổi demo/kiểm thử tải.  
* Khi credit gần hết, thu gọn hệ thống về 1 VM (control plane \+ 1 edge).  
* Chỉ tạo tài khoản AWS khi sẵn sàng triển khai, vì credit có thời hạn cố định.

  # **9\. Danh sách kiểm tra hoàn thành (Definition of Done)**

* Request đi qua edge tới origin đúng với HTTP/1.1, HTTP/2, WebSocket.  
* Chứng chỉ tự cấp và tự gia hạn cho tên miền đã xác minh.  
* Chặn/cho phép theo IP, CIDR, quốc gia, ASN; allow-list hoạt động.  
* Rate limit cục bộ và qua Redis; Redis chết thì tự hạ cấp.  
* DSL có thông báo lỗi rõ (dòng/cột), chạy được các ví dụ trong mục 5.6.  
* WAF có ít nhất các nhóm: SQLi, XSS, traversal/LFI, RCE, SSRF, bất thường giao thức; có chế độ monitor và exclusions.  
* Có số liệu TPR/FPR trên bộ mẫu và so sánh với Coraza+CRS.  
* JS challenge hoạt động, cookie ký HMAC kiểm tra được ở edge bất kỳ.  
* Under Attack tự bật/tắt đúng, origin giữ được phản hồi.  
* Cache có purge; không lưu nội dung có Set-Cookie/Authorization.  
* Cập nhật snapshot không rớt kết nối; snapshot lỗi thì giữ bản cũ; khởi động lại vẫn chạy bằng last-known-good.  
* Log không chặn request, có đếm sự kiện bị bỏ; không ghi dữ liệu nhạy cảm.  
* Metric theo từng pha, bảng điều khiển Grafana cơ bản.  
* Tải thử đạt mục tiêu độ trễ/thông lượng đã đặt (ghi số thực đo được).  
* Triển khai được ít nhất 2–3 vùng bằng Terraform và CI/CD.

  # **11\. Rủi ro và lưu ý quan trọng**

1. **Chặn nhầm (false positive)** là rủi ro thực tế lớn nhất: luôn có chế độ monitor, exclusions và log đủ lý do để gỡ.  
2. **ReDoS và tài nguyên**: chỉ dùng RE2, giới hạn kích thước regex/biểu thức/body, đặt ngân sách thời gian mỗi request.  
3. **Lạm dụng làm proxy mở/SSRF**: kiểm tra origin khi thêm và khi kết nối; chỉ phục vụ tên miền đã xác minh.  
4. **Lộ IP origin**: hướng dẫn khách khóa origin chỉ nhận lưu lượng từ edge.  
5. **Quyền riêng tư**: log chứa IP và đường dẫn; cần chính sách lưu giữ theo gói và che dữ liệu nhạy cảm.  
6. **Giấy phép dữ liệu ngoài**: GeoLite2, danh sách chặn, OWASP CRS đều có điều khoản; đọc trước khi dùng thương mại.  
7. **Giới hạn của JA3/JS challenge**: là tín hiệu và tăng chi phí cho bot, không phải bảo đảm tuyệt đối.  
8. **L3/L4 DDoS** nằm ngoài khả năng của VM thường (xem 1.5).  
9. **Phụ thuộc credit miễn phí**: lập kế hoạch thu gọn hệ thống khi credit hết hạn.  
10. **Bảo mật của chính hệ thống**: edge là mục tiêu tấn công; cập nhật Go/thư viện thường xuyên, quét lỗ hổng trong CI, tách quyền, mã hóa bí mật.

