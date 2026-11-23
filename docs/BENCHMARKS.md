# Benchmark

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
