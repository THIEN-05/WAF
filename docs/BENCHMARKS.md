# Benchmark

## P4d — giới hạn scan và coverage dev — 2026-11-23

### Xác minh trên corpus v2 (dev)

Theo chỉ dẫn mới, toàn bộ corpus v2 là **dev** vì đã bị nhìn thấy; các số cũ dưới tiêu đề “held-out v2” không còn được xem là đánh giá held-out. Không tạo corpus v3. `TestWAFCorpusMetrics` in tất cả mẫu v2 bị lọt ở paranoia 1; `TestAttackMutations` in danh sách biến thể lọt, tách theo mẫu gốc đã bắt/chưa bắt. Lệnh tự chạy và đọc đủ miss list:

```sh
go test -count=1 -v ./edge/internal/waf -run '^(TestWAFCorpusMetrics|TestAttackMutations)$'
```

Đo lại sau các luật P2 (40 mẫu mỗi nhóm, 330 mẫu sạch). FPR là 0/330 cho mỗi paranoia. TPR v2 chỉ là số dev:

| Nhóm | P1 | P2 | P3 | P4 |
| --- | ---: | ---: | ---: | ---: |
| SQLi | 55.0% | 70.0% | 70.0% | 70.0% |
| XSS | 90.0% | 100.0% | 100.0% | 100.0% |
| Traversal/LFI | 50.0% | 62.5% | 62.5% | 62.5% |
| RCE | 35.0% | 45.0% | 45.0% | 45.0% |
| Deserialization | 27.5% | 40.0% | 40.0% | 40.0% |
| RFI | 65.0% | 90.0% | 90.0% | 90.0% |
| SSRF | 80.0% | 90.0% | 90.0% | 90.0% |
| XXE | 75.0% | 75.0% | 75.0% | 75.0% |
| SSTI | 70.0% | 70.0% | 70.0% | 70.0% |
| Protocol | 100.0% | 100.0% | 100.0% | 100.0% |
| Scanner UA | 90.0% | 90.0% | 90.0% | 90.0% |
| Sensitive file | 90.0% | 90.0% | 90.0% | 90.0% |

Các nhóm mẫu v2 bị lọt gồm SQLi boolean/HAVING ở form/JSON/cookie; XSS `onpageshow`; traversal percent/double-encoding trong form/JSON; RFI/SSRF trong cookie và một số JSON; RCE newline/command variants; XXE ở JSON; SSTI/deserialization marker ở cookie/JSON; UA `httpx`; path `/config.php.orig`. Lệnh test phía trên in danh sách đầy đủ với giá trị từng mẫu. Việc mẫu nằm trong target mà luật không quét được là một phần nguyên nhân coverage thấp; body hiện là raw prefix chứ chưa parse field của JSON/multipart.

Paranoia khác nhau do các rule P2 được áp dụng ở ngưỡng tương ứng; trên v2 P2 tăng ở bảy nhóm nêu trên và FPR vẫn 0/330. P3/P4 không tăng thêm trên v2: các mẫu đó không kích hoạt các pattern nghiêm ngặt hơn. Đây không phải chứng cứ để khẳng định P3/P4 tốt hơn; cần corpus độc lập.

Mutation v2 (tự sinh, **không phải held-out**): biến thể từ mẫu gốc đã bắt **820/841 (97.5%)**; từ mẫu gốc đã lọt **61/435 (14.0%)**. Test in từng mutation miss, kể cả trạng thái phát hiện mẫu gốc.

### Giới hạn và benchmark thời gian

Scan hiện có trần request 4 KiB, mỗi mục tiêu 2 KiB, body prefix tối đa 1 KiB; query tối đa 8 KiB/64 tham số. Mục tiêu được xử lý theo URI → query → header → cookie → body; deadline được kiểm tra giữa các bước normalize và mỗi bốn rule. Body quá dài gắn `waf_body_truncated` và mặc định cộng 3 điểm (`0` hoặc bỏ trống dùng mặc định; cấu hình 1–5). Body được buffer prefix có giới hạn và phát lại trước phần dư đang stream tới origin. Test khẳng định body lớn có SQLi ngay prefix vẫn bị bắt, và origin đọc lại đủ body 8/64/256 KiB.

Benchmark p50/p99 và `allocs/op` đo trên WSL/Linux, Go 1.26.11, amd64, Intel Core i5-11400H @ 2.70 GHz; `-benchtime=100x`. Body request có kích thước entitlement 8/64/256 KiB, nhưng WAF chỉ quét prefix tối đa 1 KiB. Các số đều dưới 2 ms; hình dạng xấu nhất là 200 query params, p99 1,879,880 ns/op.

| Input | Kích thước | ns/op | p50 ns | p99 ns | B/op | allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Aho keywords lặp | 8 KiB | 266,038 | 258,347 | 360,649 | 15,990 | 42 |
| JSON lồng sâu | 8 KiB | 55,819 | 54,233 | 73,298 | 12,424 | 41 |
| Multipart nhiều phần | 8 KiB | 620,960 | 613,913 | 711,515 | 18,218 | 46 |
| Aho keywords lặp | 64 KiB | 256,143 | 253,615 | 311,142 | 15,991 | 42 |
| JSON lồng sâu | 64 KiB | 58,415 | 56,976 | 83,824 | 12,423 | 41 |
| Multipart nhiều phần | 64 KiB | 662,940 | 673,902 | 728,953 | 18,217 | 46 |
| Aho keywords lặp | 256 KiB | 251,959 | 243,782 | 322,521 | 15,990 | 42 |
| JSON lồng sâu | 256 KiB | 54,891 | 53,684 | 82,362 | 12,047 | 41 |
| Multipart nhiều phần | 256 KiB | 616,303 | 616,099 | 686,198 | 18,217 | 46 |
| 200 query params | — | 1,238,224 | 1,207,666 | 1,879,880 | 125,948 | 836 |

Lần đo ban đầu với cap body 4 KiB cho thấy multipart 256 KiB p99 2,527,739 ns/op, vượt 2 ms. Sau khi hạ trần request/mục tiêu/body từ 8/4/4 KiB xuống 4/2/1 KiB, lần đo cuối cho p99 tối đa 1,879,880 ns/op (200 tham số). Đây là phép đo 100 lần trên một máy, không phải real-time guarantee; đọc body có thể chờ client như ghi trong mục nợ kỹ thuật.

Lệnh đo:

```sh
go test -run '^$' -bench '^BenchmarkWAFWorstCase$' -benchtime=100x -benchmem ./edge/internal/waf
```

Đọc `Request.Body` đồng bộ cũng có thể chờ client gửi tiếp; số byte giới hạn bộ nhớ nhưng không cưỡng chế deadline socket. TODO-3: gắn deadline/read-timeout cho body ở listener rồi benchmark lại trên Linux.

### Corpus bên ngoài

Để đo corpus v3 do người dùng cung cấp mà không đọc hay nạp luật từ đó, đặt thư mục chỉ gồm hai file TSV rồi chạy:

```sh
WAF_CORPUS_DIR=/path/to/corpus-v3 go test -count=1 -v ./edge/internal/waf -run '^TestWAFCorpusMetrics$'
```

Định dạng mỗi dòng: `group<TAB>target<TAB>value`; cần ít nhất 40 attack samples mỗi nhóm và ít nhất 300 clean samples. `WAF_FPR_MAX` (mặc định 0) và `WAF_TPR_MIN` cấu hình ngưỡng đo. Test chỉ mở `attacks.tsv` và `clean.tsv` trong đường dẫn đã cấp; nó luôn tải managed rules của project từ `edge/rulesets`.

## Lưu trữ số đo P4c ban đầu — v2 nay là dev — 2026-11-23

Đo cũ trên Windows amd64, Go 1.26.11, Intel Core i5-11400H @ 2.70 GHz. Corpus dev hiện có 261 mẫu tấn công gốc. Tập v1 đã được dùng để nhận diện thiếu hụt và tinh chỉnh; v2 có 480 mẫu (40 mỗi nhóm, 12 nhóm) trên args/JSON/form/multipart/cookie/path/UA/protocol và 330 mẫu sạch. Theo phân loại mới, **v2 là dev**, đã bị nhìn thấy và không phải held-out. Các số dưới đây là lịch sử trước rule P2 bổ sung; bảng v2 hiện hành ở mục P4d.

> Hạn chế: tôi đã đọc pattern khi xử lý kết quả v1 trước khi soạn v2. Vì vậy v2 không độc lập và không phải held-out; cần corpus v3 do người dùng/reviewer cung cấp để đánh giá độc lập. Corpus vẫn do tác nhân tự viết, không đại diện traffic thật.

TPR đếm mẫu có tag nhóm tương ứng; FPR đếm request sạch bị bất kỳ rule nào gắn tag. Chú giải cũ “held-out” bên dưới đã lỗi thời; bảng này là số dev v2 ban đầu. `WAF_TPR_MIN` đặt ngưỡng đo, `WAF_FPR_MAX` áp dụng riêng ở cả P1–P4 (mặc định 0%):

| Nhóm tấn công | Dev v2 | P1 | P2 | P3 | P4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| SQLi | 40 | 65.0% | 65.0% | 65.0% | 65.0% |
| XSS | 40 | 90.0% | 90.0% | 90.0% | 90.0% |
| Path traversal/LFI | 40 | 50.0% | 50.0% | 50.0% | 50.0% |
| RFI | 40 | 65.0% | 65.0% | 65.0% | 65.0% |
| RCE/command injection | 40 | 42.5% | 42.5% | 42.5% | 42.5% |
| SSRF/private address | 40 | 80.0% | 80.0% | 80.0% | 80.0% |
| XXE | 40 | 75.0% | 75.0% | 75.0% | 75.0% |
| SSTI | 40 | 70.0% | 70.0% | 70.0% | 70.0% |
| Deserialization | 40 | 27.5% | 27.5% | 27.5% | 27.5% |
| Protocol anomaly | 40 | 100.0% | 100.0% | 100.0% | 100.0% |
| Scanner UA | 40 | 90.0% | 90.0% | 90.0% | 90.0% |
| Sensitive files | 40 | 90.0% | 90.0% | 90.0% | 90.0% |

Dev corpus gốc đo 261/261 (100%) cho các nhóm quy tắc ở P1–P4; marker virtual patch không có trong v2 và chỉ đạt 0% ở P1–P3 / 100% ở P4 như thiết kế. Đây là số dev, không được dùng để khẳng định khả năng bắt thực tế.

| Clean group (330 tổng) | Số mẫu | FPR P1 | FPR P2 | FPR P3 | FPR P4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Search EN/VI | 60 | 0% | 0% | 0% | 0% |
| Form | 40 | 0% | 0% | 0% | 0% |
| JSON API | 40 | 0% | 0% | 0% | 0% |
| Code/text kỹ thuật | 40 | 0% | 0% | 0% | 0% |
| Email | 30 | 0% | 0% | 0% | 0% |
| Multipart | 30 | 0% | 0% | 0% | 0% |
| Path hợp lệ (URI và text Windows/Unix) | 30 | 0% | 0% | 0% | 0% |
| URL dài | 20 | 0% | 0% | 0% | 0% |
| GraphQL | 20 | 0% | 0% | 0% | 0% |
| Base64/JWT | 20 | 0% | 0% | 0% | 0% |

Mutation tự sinh từ dev attacks: **347/347 (100.0%)** bị bắt ở biến thể còn giữ ngữ nghĩa: encode URL một/hai lần, khoảng trắng, Unicode prefix; thêm case/comment và toán tử tương đương cho SQLi; thay case tag/attribute cho XSS. Test in toàn bộ miss list nếu tỷ lệ giảm; lần đo này không có miss.

### Hiệu năng input xấu

`-benchtime=10x -benchmem`, cùng máy/toolchain. Mỗi body benchmark cấu hình chính xác giới hạn entitlement 8/64/256 KB; đo cả chuỗi lặp keyword Aho, JSON lồng sâu và multipart nhiều phần. `200_params` đo query có 200 tham số.

| Input | 8 KB ns/op | 64 KB ns/op | 256 KB ns/op | allocs/op ở 8/64/256 KB |
| --- | ---: | ---: | ---: | ---: |
| Aho keyword lặp | 2,510,930 | 14,185,830 | 29,547,040 | 53 / 63 / 88 |
| JSON lồng sâu | 2,145,570 | 7,938,140 | 13,393,910 | 49 / 58 / 76 |
| Multipart nhiều phần | 2,241,040 | 16,670,420 | 26,182,930 | 58 / 70 / 96 |
| 200 tham số | — | 3,358,360 | — | 1,113 |

Body 8/64/256 KB chạy test biên có reader trễ để chắc chắn đường budget vượt 2 ms trả `RuleID=waf_budget`, tag `waf.budget_exceeded` và hành động đúng theo fail-open/fail-closed. Test thêm 200 tham số, keyword lặp, JSON lồng sâu, multipart nhiều phần với clock có kiểm soát. Kiểm tra 3.000 request sau warm-up không làm heap tăng quá 4 MiB; benchmark báo `allocs/op` thực tế ở trên.

**Giới hạn ngân sách:** benchmark cho thấy đọc/xử lý body 64–256 KB mất nhiều hơn 2 ms (một số 8 KB cũng sát/vượt ngưỡng). Phase phát hiện quá hạn và chọn fail_mode sau bước đọc body; hiện không ngắt được việc đọc body theo deadline. `waf_budget_exceeded` được gắn vào decision/tag, nhưng pipeline chưa có sink audit bất đồng bộ để ghi sự kiện này thành log bền vững. Vì vậy chưa thể tuyên bố ngân sách 2 ms được bảo đảm cứng; đây là debt kỹ thuật.

Hai chuỗi path nhạy cảm (`C:/Windows/System32/...` và `/var/log/...`) trong tập sạch được đưa qua text body, không phải URI path: khi thử như URI, rule traversal bắt chúng (2/30). Đây là vị trí đích có ý nghĩa khác nhau; không tính request cố truy cập file hệ thống là benign. Các path URI hợp lệ còn lại không tạo false positive.

Lệnh benchmark: `go test ./edge/internal/waf -run '^$' -bench 'BenchmarkWAF(ManagedClean|ManagedEarlyExit|WorstCase)$' -benchtime=10x -benchmem`.

Các kết quả đều là corpus tự viết; chưa so với Coraza/OWASP CRS (cần mạng và TODO-1 ở dưới). Không diễn giải TPR/FPR trong bảng như tỷ lệ ngoài thực tế.

## Access check và rate limiter — 2026-11-22

Đo trên Windows amd64, Go 1.26.5, Intel Core i5-11400H @ 2.70 GHz. Mỗi benchmark chạy 5 lần; bảng báo median của `ns/op` và số cấp phát ổn định trong cả 5 lần.

| Benchmark | Median | B/op | allocs/op |
| --- | ---: | ---: | ---: |
| `BenchmarkAccessCheck` | 126.3 ns/op | 16 | 1 |
| `BenchmarkRateLimitAllow` | 725.1 ns/op | 296 | 7 |

Lệnh đo:

```sh
go test -run '^$' -bench 'Benchmark(AccessCheck|RateLimitAllow)$' -benchmem ./edge/internal/access ./edge/internal/ratelimit -count=5
```

Access benchmark lặp `Phase.Handle` trên một site/policy và IP cố định. Rate-limit benchmark gọi token bucket trên một key cố định với ngưỡng cao để đo đường cho phép. Đây là microbenchmark của hai hàm, không phải throughput request của edge.

## WAF và custom rules — P4 lượt 1 — 2026-11-22

Đo trên Windows amd64, Go 1.26.5, Intel Core i5-11400H @ 2.70 GHz, một lần chạy `-benchmem`:

| Benchmark | ns/op | B/op | allocs/op | Ghi chú |
| --- | ---: | ---: | ---: | --- |
| `BenchmarkWAF` | 3,724 | 6,501 | 27 | Request query sạch, 1 rule có Aho prefilter |
| `BenchmarkRules` | 6,609 | 0 | 0 | 128 custom rule `log`, báo thêm 19.37M rule-eval/s |

Lệnh đo: `go test -run '^$' -bench 'Benchmark(WAF|Rules)$' -benchmem ./edge/internal/waf ./edge/internal/rules`.

Đây là baseline microbenchmark trên Go mới hơn mức yêu cầu tương thích 1.22.8; race test chưa chạy được trong session này do WSL trả `E_ACCESSDENIED` và Windows host thiếu CGO, vì vậy chưa có số đo/kiểm chứng Go 1.22.8 tại đây.

## WAF managed rules — P4 lượt 2 — 2026-11-22

Đo trên Windows amd64, Go 1.26.11, Intel Core i5-11400H @ 2.70 GHz; median của 5 lần chạy `-benchmem`. Bộ luật nhúng có 19 rule. Cả hai benchmark cấu hình ngân sách WAF 2 ms.

| Benchmark | Median ns/op | B/op | allocs/op | Request |
| --- | ---: | ---: | ---: | --- |
| `BenchmarkWAFManagedClean` | 25,462 | 6,831 | 28 | GET tìm kiếm sạch, toàn bộ managed rules ở paranoia 1 |
| `BenchmarkWAFManagedEarlyExit` | 10,134 | 7,093 | 38 | GET có `UNION SELECT`, sensitivity high, dừng khi đạt ngưỡng |

Lệnh đo: `go test -run '^$' -bench '^BenchmarkWAFManaged(Clean|EarlyExit)$' -benchmem ./edge/internal/waf -count=5`.

### Đo TPR/FPR trên corpus tự viết

Lệnh: `go test -count=1 -v ./edge/internal/waf -run TestManagedCorpusTPRFPR`. Attack corpus có 20 mẫu mỗi nhóm (deserialization có 21), clean corpus có 46 mẫu. TPR được đo ở từng paranoia, trên các rule match chứ không dựa vào action block; baseline trong `test/corpus/waf/tpr-baseline.json` được khóa theo lần đo này. TPR dưới baseline làm test đỏ. Mức `WAF_TPR_MIN` (phân số 0..1, mặc định 0) có thể tăng thêm mức tối thiểu; nó không thể hạ baseline đã ghi. `WAF_FPR_MAX` (phân số 0..1, mặc định 0) cấu hình trần FPR; paranoia 1 vượt trần làm test đỏ.

| Nhóm tấn công | Mẫu | P1 | P2 | P3 | P4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| SQLi | 20 | 100% | 100% | 100% | 100% |
| XSS | 20 | 100% | 100% | 100% | 100% |
| Path traversal/LFI | 20 | 100% | 100% | 100% | 100% |
| RFI | 20 | 100% | 100% | 100% | 100% |
| RCE/command injection | 20 | 100% | 100% | 100% | 100% |
| SSRF/private & metadata | 20 | 100% | 100% | 100% | 100% |
| XXE | 20 | 100% | 100% | 100% | 100% |
| SSTI | 20 | 100% | 100% | 100% | 100% |
| Deserialization | 21 | 100% | 100% | 100% | 100% |
| Protocol anomaly/smuggling | 20 | 100% | 100% | 100% | 100% |
| Scanner User-Agent | 20 | 100% | 100% | 100% | 100% |
| Sensitive files | 20 | 100% | 100% | 100% | 100% |
| Virtual patch template marker | 20 | 0% | 0% | 0% | 100% |

| Clean group | Mẫu | FPR P1 | FPR P2 | FPR P3 | FPR P4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| Form | 10 | 0% | 0% | 0% | 0% |
| JSON | 10 | 0% | 0% | 0% | 0% |
| Search | 10 | 0% | 0% | 0% | 0% |
| Valid paths | 8 | 0% | 0% | 0% | 0% |
| Headers | 3 | 0% | 0% | 0% | 0% |
| Text body | 5 | 0% | 0% | 0% | 0% |

Đây là độ đo trên bộ mẫu ngắn, tự viết để kiểm tra hồi quy; 100% không phải ước lượng tỷ lệ bắt được trên lưu lượng thực tế. Bộ sạch có các từ `select`, `union`, `drop`, tìm kiếm có dấu nháy, tên như `O'Neil`, JSON/form và đường dẫn hợp lệ. Các test né tránh bao gồm URL mã hóa kép, hoa/thường, comment SQL xen kẽ, whitespace lạ, NUL, Unicode và CL+TE.

- TODO-1: so sánh cùng corpus với Coraza + OWASP CRS, ghi phiên bản CRS và TPR/FPR theo nhóm; cần tải/cài dependency từ mạng.
