# Benchmark

## Kiểm chứng WAF P4c — corpus v2 — 2026-11-23

Đo trên Windows amd64, Go 1.26.11, Intel Core i5-11400H @ 2.70 GHz. Corpus dev hiện có 261 mẫu tấn công gốc. Held-out v1 (40 mẫu mỗi nhóm) đã được dùng để nhận diện thiếu hụt và tinh chỉnh; bản này được lưu thành `test/corpus/waf/dev/heldout-v1-attacks.tsv` và không còn được tính là held-out. Held-out v2 được tạo sau tinh chỉnh, có 480 mẫu (40 mỗi nhóm, 12 nhóm) trên args/JSON/form/multipart/cookie/path/UA/protocol và được đóng băng; 330 mẫu sạch đo FPR ở mọi paranoia. Không có chỉnh luật sau phép đo v2.

> Giới hạn độc lập: tôi đã đọc các pattern khi xử lý kết quả v1 trước khi soạn v2. Vì vậy v2 là hậu nghiệm và không bị tinh chỉnh theo kết quả của chính nó, nhưng quy trình soạn không hoàn toàn blind như yêu cầu; cần một người đánh giá độc lập tạo corpus v3 để có kiểm chứng mù thực sự. Corpus vẫn do tác nhân tự viết, không đại diện traffic thật.

TPR đếm mẫu có tag nhóm tương ứng; FPR đếm request sạch bị bất kỳ rule nào gắn tag. Held-out baseline được ghi trong `test/corpus/waf/heldout/tpr-baseline.json`; `WAF_TPR_MIN` có thể đặt ngưỡng cao hơn, `WAF_FPR_MAX` áp dụng riêng ở cả P1–P4 (mặc định 0%). Bảng held-out v2 (cùng kết quả ở mọi paranoia vì các rule này bật từ P1):

| Nhóm tấn công | Held-out | P1 | P2 | P3 | P4 |
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

Dev corpus gốc đo 261/261 (100%) cho các nhóm quy tắc ở P1–P4; marker virtual patch không có trong held-out, và chỉ đạt 0% ở P1–P3 / 100% ở P4 như thiết kế. Đây là số của corpus dev, không được dùng để khẳng định khả năng bắt thực tế.

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
